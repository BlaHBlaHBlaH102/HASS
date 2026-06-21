// ============================================================
// HASS - Rate & Flow Monitor
// Maintains per-flow state for 64 concurrent flows
// Flags: ARP spoofing, SYN flood, C2 beaconing
// Target: Artix-7 XC7A100T @ 125 MHz
// ============================================================

module rate_monitor (
    input  wire        clk,
    input  wire        rst_n,

    // Parsed header fields from hass_top packet parser
    input  wire [31:0] src_ip,
    input  wire [31:0] dst_ip,
    input  wire [15:0] src_port,
    input  wire [15:0] dst_port,
    input  wire [7:0]  protocol,    // 0x06=TCP, 0x11=UDP, 0x00=ARP
    input  wire        pkt_valid,   // pulse: new packet header available
    input  wire        is_syn,      // TCP SYN flag set
    input  wire        is_syn_ack,  // TCP SYN-ACK flag set
    input  wire        is_arp_reply,// ARP opcode = 2

    // Alert outputs
    output reg         rate_alert,
    output reg [1:0]   alert_type   // 0=ARP spoof, 1=SYN flood, 2=C2 beacon
);

    // ----------------------------------------------------------
    // Flow table: 64 slots, indexed by hash of 4-tuple
    // Each slot stores:
    //   src_ip, dst_ip, src_port, dst_port (for collision check)
    //   pkt_count   — total packets this flow
    //   syn_count   — SYN packets seen
    //   synack_count— SYN-ACK packets seen
    //   byte_count  — total bytes (from hass_top, not shown here)
    //   age_timer   — counts down; slot freed when zero
    // ----------------------------------------------------------
    localparam FLOW_SLOTS = 64;
    localparam SLOT_BITS  = 6;   // log2(64)

    // Flow table registers
    reg [31:0] ft_src_ip    [0:FLOW_SLOTS-1];
    reg [31:0] ft_dst_ip    [0:FLOW_SLOTS-1];
    reg [15:0] ft_src_port  [0:FLOW_SLOTS-1];
    reg [15:0] ft_dst_port  [0:FLOW_SLOTS-1];
    reg [15:0] ft_pkt_count [0:FLOW_SLOTS-1];
    reg [7:0]  ft_syn_count [0:FLOW_SLOTS-1];
    reg [7:0]  ft_synack    [0:FLOW_SLOTS-1];
    reg [15:0] ft_age       [0:FLOW_SLOTS-1];
    reg        ft_valid     [0:FLOW_SLOTS-1]; // slot occupied

    // ARP reply rate counter (global, not per-flow)
    reg [7:0]  arp_reply_count;
    reg [19:0] arp_window_timer;    // ~8ms window @ 125 MHz

    // Thresholds
    localparam ARP_THRESH    = 8'd20;   // >20 ARP replies per 8ms = spoofing
    localparam SYN_THRESH    = 8'd30;   // >30 SYNs with <5 SYN-ACKs = flood
    localparam BEACON_THRESH = 16'd50;  // >50 pkts/window to same dst = beaconing
    localparam FLOW_AGE_MAX  = 16'hFFFF;

    // ----------------------------------------------------------
    // Hash function: XOR fold of 4-tuple to 6-bit slot index
    // Simple but sufficient for 64-slot table
    // ----------------------------------------------------------
    function [SLOT_BITS-1:0] flow_hash;
        input [31:0] sip;
        input [31:0] dip;
        input [15:0] sp;
        input [15:0] dp;
        reg [31:0] h;
        begin
            h = sip ^ dip ^ {sp, dp};
            flow_hash = h[5:0] ^ h[11:6] ^ h[17:12] ^ h[23:18] ^ {4'b0, h[25:24]};
        end
    endfunction

    // ----------------------------------------------------------
    // Slot lookup: find matching slot or first empty
    // Returns slot index and hit/miss flag
    // Done combinatorially — 64-entry CAM scan
    // ----------------------------------------------------------
    reg [SLOT_BITS-1:0] hash_idx;
    reg [SLOT_BITS-1:0] matched_slot;
    reg                 slot_hit;
    reg [SLOT_BITS-1:0] free_slot;
    reg                 free_found;

    integer s;
    always @(*) begin
        hash_idx     = flow_hash(src_ip, dst_ip, src_port, dst_port);
        matched_slot = 0;
        slot_hit     = 0;
        free_slot    = 0;
        free_found   = 0;

        for (s = 0; s < FLOW_SLOTS; s = s + 1) begin
            if (ft_valid[s] &&
                ft_src_ip[s]   == src_ip   &&
                ft_dst_ip[s]   == dst_ip   &&
                ft_src_port[s] == src_port &&
                ft_dst_port[s] == dst_port) begin
                matched_slot = s[SLOT_BITS-1:0];
                slot_hit     = 1;
            end
            if (!ft_valid[s] && !free_found) begin
                free_slot  = s[SLOT_BITS-1:0];
                free_found = 1;
            end
        end
    end

    // ----------------------------------------------------------
    // ARP reply rate monitor (global window)
    // ----------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            arp_reply_count  <= 0;
            arp_window_timer <= 0;
        end else begin
            if (arp_window_timer == 20'hFFFFF) begin
                arp_window_timer <= 0;
                arp_reply_count  <= 0;
            end else begin
                arp_window_timer <= arp_window_timer + 1;
            end

            if (pkt_valid && is_arp_reply) begin
                arp_reply_count <= arp_reply_count + 1;
            end
        end
    end

    // ----------------------------------------------------------
    // Per-flow state update + alert FSM
    // ----------------------------------------------------------
    integer j;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            rate_alert <= 0;
            alert_type <= 0;
            for (j = 0; j < FLOW_SLOTS; j = j + 1) begin
                ft_valid[j]     <= 0;
                ft_pkt_count[j] <= 0;
                ft_syn_count[j] <= 0;
                ft_synack[j]    <= 0;
                ft_age[j]       <= 0;
                ft_src_ip[j]    <= 0;
                ft_dst_ip[j]    <= 0;
                ft_src_port[j]  <= 0;
                ft_dst_port[j]  <= 0;
            end
        end else begin

            // Age all flows every cycle (decrement timer)
            for (j = 0; j < FLOW_SLOTS; j = j + 1) begin
                if (ft_valid[j]) begin
                    if (ft_age[j] == 0)
                        ft_valid[j] <= 0;  // expire old flow
                    else
                        ft_age[j] <= ft_age[j] - 1;
                end
            end

            // ARP spoof check — purely rate based, no flow needed
            if (pkt_valid && is_arp_reply && (arp_reply_count >= ARP_THRESH)) begin
                rate_alert <= 1;
                alert_type <= 2'd0;
            end

            // Per-packet flow update
            if (pkt_valid && !is_arp_reply) begin
                if (slot_hit) begin
                    // Update existing flow
                    ft_pkt_count[matched_slot] <= ft_pkt_count[matched_slot] + 1;
                    ft_age[matched_slot]        <= FLOW_AGE_MAX;

                    if (is_syn)
                        ft_syn_count[matched_slot] <= ft_syn_count[matched_slot] + 1;
                    if (is_syn_ack)
                        ft_synack[matched_slot] <= ft_synack[matched_slot] + 1;

                    $display("    DEBUG: slot=%0d syn_count=%0d synack=%0d pkt_count=%0d",
                             matched_slot, ft_syn_count[matched_slot], ft_synack[matched_slot],
                             ft_pkt_count[matched_slot]);

                    // SYN flood: many SYNs, very few SYN-ACKs
                    if ((ft_syn_count[matched_slot] + (is_syn ? 1 : 0)) >= SYN_THRESH &&
                        (ft_synack[matched_slot] + (is_syn_ack ? 1 : 0)) < 8'd5) begin
                        rate_alert <= 1;
                        alert_type <= 2'd1;
                    end


                    // C2 beaconing: abnormally high packet rate to same dst
                    // ft_pkt_count is unconditionally incremented above, so always +1 here
                    if ((ft_pkt_count[matched_slot] + 1) >= BEACON_THRESH) begin
                        rate_alert <= 1;
                        alert_type <= 2'd2;
                    end

                end else if (free_found) begin
                    // Insert new flow into free slot
                    ft_valid[free_slot]     <= 1;
                    ft_src_ip[free_slot]    <= src_ip;
                    ft_dst_ip[free_slot]    <= dst_ip;
                    ft_src_port[free_slot]  <= src_port;
                    ft_dst_port[free_slot]  <= dst_port;
                    ft_pkt_count[free_slot] <= 1;
                    ft_syn_count[free_slot] <= is_syn ? 1 : 0;
                    ft_synack[free_slot]    <= is_syn_ack ? 1 : 0;
                    ft_age[free_slot]       <= FLOW_AGE_MAX;
                end
                // If no free slot and no hit: table full, packet untracked
                // This is acceptable — degrades gracefully under flood conditions
            end
        end
    end

endmodule

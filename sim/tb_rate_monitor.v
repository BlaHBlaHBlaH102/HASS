`timescale 1ns/1ps

module tb_rate_monitor;

    reg        clk         = 0;
    reg        rst_n       = 0;
    reg [31:0] src_ip      = 0;
    reg [31:0] dst_ip      = 0;
    reg [15:0] src_port    = 0;
    reg [15:0] dst_port    = 0;
    reg [7:0]  protocol    = 0;
    reg        pkt_valid   = 0;
    reg        is_syn      = 0;
    reg        is_syn_ack  = 0;
    reg        is_arp_reply= 0;

    wire        rate_alert;
    wire [1:0]  alert_type;

    rate_monitor u_dut (
        .clk          (clk),
        .rst_n        (rst_n),
        .src_ip       (src_ip),
        .dst_ip       (dst_ip),
        .src_port     (src_port),
        .dst_port     (dst_port),
        .protocol     (protocol),
        .pkt_valid    (pkt_valid),
        .is_syn       (is_syn),
        .is_syn_ack   (is_syn_ack),
        .is_arp_reply (is_arp_reply),
        .rate_alert   (rate_alert),
        .alert_type   (alert_type)
    );

    always #4 clk = ~clk;  // 125 MHz

    initial begin
        $dumpfile("tb_rate_monitor.vcd");
        $dumpvars(0, tb_rate_monitor);
    end

    // Sends one "packet" -- pulses pkt_valid for one cycle with
    // whatever header fields are currently set
    task send_packet;
        begin
            @(posedge clk);
            pkt_valid <= 1;
            @(posedge clk);
            pkt_valid <= 0;
        end
    endtask

    integer k;

    initial begin
        rst_n = 0;
        repeat(4) @(posedge clk);
        rst_n = 1;
        repeat(2) @(posedge clk);

        // -------------------------------------------------------
        // TEST 1: new flow insertion
        // -------------------------------------------------------
        $display("--- TEST 1: new flow insertion ---");
        src_ip   = 32'hC0A80101;  // 192.168.1.1
        dst_ip   = 32'h08080808;  // 8.8.8.8
        src_port = 16'd5000;
        dst_port = 16'd443;
        protocol = 8'h06;
        is_syn = 0; is_syn_ack = 0; is_arp_reply = 0;
        send_packet;
        repeat(2) @(posedge clk);

        $display("  u_dut.ft_valid[free_slot guess 0]=%b pkt_count[0]=%0d",
                  u_dut.ft_valid[0], u_dut.ft_pkt_count[0]);

        // -------------------------------------------------------
        // TEST 2: same flow again -- should update slot 0, not
        // create a second entry. pkt_count should go to 2.
        // -------------------------------------------------------
        $display("--- TEST 2: repeat same flow (expect pkt_count=2, same slot) ---");
        send_packet;
        repeat(2) @(posedge clk);
        $display("  ft_valid[0]=%b pkt_count[0]=%0d ft_valid[1]=%b",
                  u_dut.ft_valid[0], u_dut.ft_pkt_count[0], u_dut.ft_valid[1]);

        // -------------------------------------------------------
        // TEST 3: ARP spoofing -- send ARP_THRESH+1 = 21 ARP replies
        // -------------------------------------------------------
        $display("--- TEST 3: ARP spoof flood (21x ARP replies) ---");
        is_arp_reply = 1;
        for (k = 0; k < 21; k = k + 1) begin
            send_packet;
        end
        repeat(2) @(posedge clk);
        $display("  rate_alert=%b alert_type=%0d (expect 1, type=0 ARP spoof)",
                  rate_alert, alert_type);
        is_arp_reply = 0;
        repeat(4) @(posedge clk);

        // -------------------------------------------------------
        // TEST 4: SYN flood -- same NEW flow, 30+ SYNs, <5 SYN-ACKs
        // -------------------------------------------------------
        $display("--- TEST 4: SYN flood (31x SYN, 0x SYN-ACK, new flow) ---");
        src_ip   = 32'h0A000001;  // 10.0.0.1
        dst_ip   = 32'h0A000002;  // 10.0.0.2
        src_port = 16'd6000;
        dst_port = 16'd80;
        is_syn = 1; is_syn_ack = 0;
        for (k = 0; k < 31; k = k + 1) begin
            send_packet;
        end
        repeat(2) @(posedge clk);
        $display("  rate_alert=%b alert_type=%0d (expect 1, type=1 SYN flood)",
                  rate_alert, alert_type);
        is_syn = 0;
        repeat(4) @(posedge clk);

        // -------------------------------------------------------
        // TEST 5: C2 beaconing -- same flow, 50+ plain packets
        // -------------------------------------------------------
        $display("--- TEST 5: C2 beaconing (51x plain packets, same flow) ---");
        src_ip   = 32'hAC100001;  // 172.16.0.1
        dst_ip   = 32'hAC100002;  // 172.16.0.2
        src_port = 16'd7000;
        dst_port = 16'd4444;
        is_syn = 0; is_syn_ack = 0;
        for (k = 0; k < 51; k = k + 1) begin
            send_packet;
        end
        repeat(2) @(posedge clk);
        $display("  rate_alert=%b alert_type=%0d (expect 1, type=2 beaconing)",
                  rate_alert, alert_type);

        $display("Simulation complete.");
        $finish;
    end

endmodule
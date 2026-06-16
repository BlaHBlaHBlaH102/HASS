// ============================================================
// HASS - DNS Protocol Parser + Sinkhole Engine
// Decodes DNS queries per RFC 1035 (including compressed labels)
// Flags: DNS rebinding, NXDOMAIN flood, known-bad domain match
// Sinkhole: forges DNS response pointing to 192.168.254.1
// Target: Artix-7 XC7A100T @ 125 MHz
// ============================================================

module dns_parser (
    input  wire        clk,
    input  wire        rst_n,

    // Byte stream from TEMAC (UDP payload only — parser assumes
    // Ethernet/IP/UDP headers already stripped by hass_top)
    input  wire [7:0]  byte_in,
    input  wire        byte_valid,
    input  wire        frame_start,
    input  wire        frame_end,

    // Signal from Aho-Corasick: domain in current query is on no-fly list
    input  wire        ac_match,

    // Alert and sinkhole outputs
    output reg         dns_alert,        // any DNS threat flag
    output reg         sinkhole_active,  // tell TEMAC to forge response
    output reg [31:0]  sinkhole_ip,      // always 192.168.254.1

    // NXDOMAIN flood tracking (counts per frame window)
    output reg [7:0]   nxdomain_count
);

    // ----------------------------------------------------------
    // Sinkhole IP is fixed — MicroBlaze warning page lives here
    // ----------------------------------------------------------
    localparam SINKHOLE_ADDR = 32'hC0A8FE01;  // 192.168.254.1

    // ----------------------------------------------------------
    // RFC 1035 DNS header offsets (all fields big-endian)
    // Byte 0-1  : Transaction ID
    // Byte 2-3  : Flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE)
    // Byte 4-5  : QDCOUNT
    // Byte 6-7  : ANCOUNT
    // Byte 8-9  : NSCOUNT
    // Byte 10-11: ARCOUNT
    // Byte 12+  : Question section (QNAME, QTYPE, QCLASS)
    // ----------------------------------------------------------

    // Parser FSM states
    localparam S_IDLE       = 4'd0;
    localparam S_HDR        = 4'd1;   // consuming 12-byte header
    localparam S_QNAME      = 4'd2;   // reading label sequence
    localparam S_LABEL_DATA = 4'd3;   // consuming label bytes
    localparam S_QTYPE_HI   = 4'd4;   // QTYPE high byte
    localparam S_QTYPE_LO   = 4'd5;   // QTYPE low byte
    localparam S_QCLASS_HI  = 4'd6;
    localparam S_QCLASS_LO  = 4'd7;
    localparam S_ANSWER     = 4'd8;   // scanning answer section
    localparam S_RDATA      = 4'd9;   // reading RDATA (check for RFC-1918)
    localparam S_DONE       = 4'd10;

    reg [3:0]  state;
    reg [3:0]  byte_idx;       // position within current header field
    reg [7:0]  label_len;      // current label length byte
    reg [7:0]  label_remaining;// bytes left in current label
    reg [7:0]  hdr_count;      // counts through 12-byte header

    // Extracted header fields
    reg [15:0] tx_id;
    reg [15:0] flags;
    reg [15:0] qdcount;
    reg [15:0] ancount;
    reg [3:0]  rcode;          // response code (NXDOMAIN = 3)
    reg        is_response;    // QR bit

    // Answer section RDATA capture (for rebinding check)
    reg [31:0] rdata_ip;
    reg [7:0]  rdata_byte_idx;

    // NXDOMAIN flood: count responses with RCODE=3 in a time window
    // Window = 65536 clock cycles (~524us @ 125MHz), reset on overflow
    reg [15:0] nxdomain_window_timer;
    localparam NXDOMAIN_THRESH = 8'd10;   // >10 NXDOMAINs per window = flood

    // ----------------------------------------------------------
    // RFC-1918 check: is an IP in a private range?
    // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    // ----------------------------------------------------------
    function is_rfc1918;
        input [31:0] ip;
        begin
            is_rfc1918 = (ip[31:24] == 8'd10) ||
                         (ip[31:24] == 8'd172 && ip[23:20] == 4'd1) ||
                         (ip[31:24] == 8'd192 && ip[23:16] == 8'd168);
        end
    endfunction

    // ----------------------------------------------------------
    // Main parser FSM
    // ----------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state             <= S_IDLE;
            byte_idx          <= 0;
            hdr_count         <= 0;
            label_len         <= 0;
            label_remaining   <= 0;
            tx_id             <= 0;
            flags             <= 0;
            qdcount           <= 0;
            ancount           <= 0;
            rcode             <= 0;
            is_response       <= 0;
            rdata_ip          <= 0;
            rdata_byte_idx    <= 0;
            dns_alert         <= 0;
            sinkhole_active   <= 0;
            sinkhole_ip       <= SINKHOLE_ADDR;
            nxdomain_count    <= 0;
            nxdomain_window_timer <= 0;
        end else begin

            // Default: deassert pulse signals each cycle
            dns_alert       <= 0;
            sinkhole_active <= 0;

            // NXDOMAIN flood window timer — free-running
            if (nxdomain_window_timer == 16'hFFFF) begin
                nxdomain_window_timer <= 0;
                nxdomain_count        <= 0;  // reset count each window
            end else begin
                nxdomain_window_timer <= nxdomain_window_timer + 1;
            end

            if (frame_start) begin
                state      <= S_HDR;
                hdr_count  <= 0;
                byte_idx   <= 0;
            end else if (byte_valid) begin
                case (state)

                    // ------------------------------------------
                    // Consume 12-byte DNS header
                    // ------------------------------------------
                    S_HDR: begin
                        case (hdr_count)
                            8'd0:  tx_id[15:8]  <= byte_in;
                            8'd1:  tx_id[7:0]   <= byte_in;
                            8'd2: begin
                                flags[15:8] <= byte_in;
                                is_response <= byte_in[7]; // QR bit
                            end
                            8'd3: begin
                                flags[7:0] <= byte_in;
                                rcode      <= byte_in[3:0];
                            end
                            8'd4:  qdcount[15:8] <= byte_in;
                            8'd5:  qdcount[7:0]  <= byte_in;
                            8'd6:  ancount[15:8] <= byte_in;
                            8'd7:  ancount[7:0]  <= byte_in;
                            // NSCOUNT and ARCOUNT ignored
                        endcase

                        if (hdr_count == 8'd11) begin
                            hdr_count <= 0;
                            // Check for NXDOMAIN flood on response packets
                            if (is_response && rcode == 4'd3) begin
                                nxdomain_count <= nxdomain_count + 1;
                                if (nxdomain_count >= NXDOMAIN_THRESH) begin
                                    dns_alert <= 1;
                                end
                            end
                            state <= S_QNAME;
                        end else begin
                            hdr_count <= hdr_count + 1;
                        end
                    end

                    // ------------------------------------------
                    // QNAME: sequence of length-prefixed labels
                    // terminated by 0x00 or a compression pointer
                    // (top two bits = 11 signals pointer per RFC 1035)
                    // ------------------------------------------
                    S_QNAME: begin
                        if (byte_in == 8'h00) begin
                            // Root label — end of QNAME
                            state <= S_QTYPE_HI;
                        end else if (byte_in[7:6] == 2'b11) begin
                            // Compression pointer — skip one more byte
                            // then move to QTYPE (we don't follow pointers
                            // in hardware; AC engine handles domain matching)
                            label_remaining <= 1;
                            state           <= S_LABEL_DATA;
                            // After label_data drains, go to QTYPE
                        end else begin
                            // Normal label: byte_in is length
                            label_len       <= byte_in;
                            label_remaining <= byte_in;
                            state           <= S_LABEL_DATA;
                        end
                    end

                    S_LABEL_DATA: begin
                        if (label_remaining == 1) begin
                            state <= S_QNAME;  // back to read next length byte
                        end else begin
                            label_remaining <= label_remaining - 1;
                        end
                    end

                    S_QTYPE_HI:  state <= S_QTYPE_LO;   // ignore QTYPE value
                    S_QTYPE_LO:  state <= S_QCLASS_HI;
                    S_QCLASS_HI: state <= S_QCLASS_LO;
                    S_QCLASS_LO: begin
                        // Done with question section
                        // If AC engine matched this domain, sinkhole it
                        if (ac_match) begin
                            dns_alert       <= 1;
                            sinkhole_active <= 1;
                            sinkhole_ip     <= SINKHOLE_ADDR;
                        end
                        // If this is a response, scan answer section
                        // for DNS rebinding (public name -> RFC-1918 IP)
                        if (is_response && ancount > 0) begin
                            rdata_byte_idx <= 0;
                            state          <= S_ANSWER;
                        end else begin
                            state <= S_DONE;
                        end
                    end

                    // ------------------------------------------
                    // Answer section: skip NAME (compressed, 2 bytes)
                    // TYPE (2), CLASS (2), TTL (4), RDLENGTH (2)
                    // then read RDATA for A-record rebinding check
                    // Total header before RDATA = 12 bytes
                    // ------------------------------------------
                    S_ANSWER: begin
                        rdata_byte_idx <= rdata_byte_idx + 1;
                        if (rdata_byte_idx == 8'd11) begin
                            // About to read RDATA — reset for IP capture
                            rdata_byte_idx <= 0;
                            rdata_ip       <= 0;
                            state          <= S_RDATA;
                        end
                    end

                    // ------------------------------------------
                    // Capture 4-byte A record RDATA and check
                    // for RFC-1918 address (DNS rebinding attack)
                    // ------------------------------------------
                    S_RDATA: begin
                        case (rdata_byte_idx)
                            8'd0: rdata_ip[31:24] <= byte_in;
                            8'd1: rdata_ip[23:16] <= byte_in;
                            8'd2: rdata_ip[15:8]  <= byte_in;
                            8'd3: begin
                                rdata_ip[7:0] <= byte_in;
                                // Check complete IP for rebinding
                                if (is_rfc1918({rdata_ip[31:8], byte_in})) begin
                                    dns_alert <= 1;
                                end
                                state <= S_DONE;
                            end
                        endcase
                        rdata_byte_idx <= rdata_byte_idx + 1;
                    end

                    S_DONE: begin
                        // Hold until frame_end resets via frame_start
                    end

                    default: state <= S_IDLE;
                endcase
            end
        end
    end

endmodule

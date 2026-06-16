// ============================================================
// HASS - Packet Header Parser
// Strips Ethernet, IP, TCP/UDP headers from raw byte stream
// Presents parsed fields as registered outputs to engines
// Target: Artix-7 XC7A100T @ 125 MHz
// ============================================================

module pkt_header_parser (
    input  wire        clk,
    input  wire        rst_n,

    // Raw byte stream from TEMAC
    input  wire [7:0]  byte_in,
    input  wire        byte_valid,
    input  wire        frame_start,  // pulse: start of new Ethernet frame
    input  wire        frame_end,    // pulse: end of frame

    // Parsed fields — registered, stable for duration of frame
    output reg [31:0]  src_ip,
    output reg [31:0]  dst_ip,
    output reg [15:0]  src_port,
    output reg [15:0]  dst_port,
    output reg [7:0]   protocol,     // 0x06=TCP, 0x11=UDP, 0x01=ICMP

    // TCP flag outputs (valid only when protocol == 0x06)
    output reg         is_syn,
    output reg         is_syn_ack,
    output reg         is_ack,
    output reg         is_fin,
    output reg         is_rst,

    // ARP outputs
    output reg         is_arp_reply, // ARP opcode == 2

    // Payload stream — byte stream forwarded AFTER all headers stripped
    // Engines connect here instead of to raw TEMAC output
    output reg [7:0]   payload_byte,
    output reg         payload_valid,
    output reg         payload_start, // pulses on first payload byte
    output reg         payload_end,   // mirrors frame_end

    // Header parse complete — safe to read all output fields
    output reg         hdr_valid
);

    // ----------------------------------------------------------
    // Ethernet header layout (14 bytes, no VLAN)
    // Byte 0-5  : Destination MAC
    // Byte 6-11 : Source MAC
    // Byte 12-13: EtherType
    //   0x0800 = IPv4
    //   0x0806 = ARP
    // ----------------------------------------------------------

    // ----------------------------------------------------------
    // IPv4 header layout (20 bytes minimum, no options handled)
    // Byte 0    : Version (4) + IHL (header length in 32-bit words)
    // Byte 1    : DSCP + ECN
    // Byte 2-3  : Total length
    // Byte 4-5  : Identification
    // Byte 6-7  : Flags + Fragment offset
    // Byte 8    : TTL
    // Byte 9    : Protocol
    // Byte 10-11: Header checksum
    // Byte 12-15: Source IP
    // Byte 16-19: Destination IP
    // ----------------------------------------------------------

    // ----------------------------------------------------------
    // TCP header layout (20 bytes minimum)
    // Byte 0-1  : Source port
    // Byte 2-3  : Destination port
    // Byte 4-7  : Sequence number
    // Byte 8-11 : Acknowledgment number
    // Byte 12   : Data offset (header length in 32-bit words) + reserved
    // Byte 13   : Flags (URG ACK PSH RST SYN FIN)
    // Byte 14-15: Window size
    // Byte 16-17: Checksum
    // Byte 18-19: Urgent pointer
    // ----------------------------------------------------------

    // ----------------------------------------------------------
    // UDP header layout (8 bytes)
    // Byte 0-1  : Source port
    // Byte 2-3  : Destination port
    // Byte 4-5  : Length
    // Byte 6-7  : Checksum
    // ----------------------------------------------------------

    // ----------------------------------------------------------
    // ARP header layout (28 bytes for IPv4)
    // Byte 0-1  : Hardware type
    // Byte 2-3  : Protocol type
    // Byte 4    : Hardware addr length
    // Byte 5    : Protocol addr length
    // Byte 6-7  : Opcode (1=request, 2=reply)
    // Byte 8-13 : Sender MAC
    // Byte 14-17: Sender IP
    // Byte 18-23: Target MAC
    // Byte 24-27: Target IP
    // ----------------------------------------------------------

    // ----------------------------------------------------------
    // Parser FSM states
    // ----------------------------------------------------------
    localparam S_IDLE        = 4'd0;
    localparam S_ETH_HDR     = 4'd1;   // consuming 14-byte Ethernet header
    localparam S_IP_HDR      = 4'd2;   // consuming 20-byte IPv4 header
    localparam S_TCP_HDR     = 4'd3;   // consuming 20-byte TCP header
    localparam S_UDP_HDR     = 4'd4;   // consuming 8-byte UDP header
    localparam S_ARP_HDR     = 4'd5;   // consuming 28-byte ARP payload
    localparam S_PAYLOAD     = 4'd6;   // forwarding payload bytes to engines
    localparam S_SKIP        = 4'd7;   // unknown EtherType — discard frame

    reg [3:0]  state;
    reg [7:0]  byte_count;   // position within current header section

    // Latched EtherType and IP fields needed across states
    reg [15:0] ethertype;
    reg [7:0]  ihl_bytes;    // IP header length in bytes (IHL field * 4)
    reg [7:0]  ip_hdr_remaining; // counts down through variable IP header
    reg [7:0]  tcp_data_offset_bytes; // TCP header length in bytes
    reg [7:0]  tcp_hdr_remaining;

    // ----------------------------------------------------------
    // Main parser FSM
    // ----------------------------------------------------------
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state                 <= S_IDLE;
            byte_count            <= 0;
            ethertype             <= 0;
            ihl_bytes             <= 0;
            ip_hdr_remaining      <= 0;
            tcp_data_offset_bytes <= 0;
            tcp_hdr_remaining     <= 0;
            src_ip                <= 0;
            dst_ip                <= 0;
            src_port              <= 0;
            dst_port              <= 0;
            protocol              <= 0;
            is_syn                <= 0;
            is_syn_ack            <= 0;
            is_ack                <= 0;
            is_fin                <= 0;
            is_rst                <= 0;
            is_arp_reply          <= 0;
            payload_byte          <= 0;
            payload_valid         <= 0;
            payload_start         <= 0;
            payload_end           <= 0;
            hdr_valid             <= 0;
        end else begin

            // Default: deassert pulse outputs each cycle
            payload_valid <= 0;
            payload_start <= 0;
            payload_end   <= 0;
            hdr_valid     <= 0;

            if (frame_start) begin
                state      <= S_ETH_HDR;
                byte_count <= 0;
                // Clear all parsed fields at start of new frame
                src_ip       <= 0;
                dst_ip       <= 0;
                src_port     <= 0;
                dst_port     <= 0;
                protocol     <= 0;
                is_syn       <= 0;
                is_syn_ack   <= 0;
                is_ack       <= 0;
                is_fin       <= 0;
                is_rst       <= 0;
                is_arp_reply <= 0;
            end else if (frame_end) begin
                payload_end <= 1;
                state       <= S_IDLE;
            end else if (byte_valid) begin
                case (state)

                    // ------------------------------------------
                    // Ethernet header: 14 bytes
                    // Bytes 0-5:  dst MAC (ignored)
                    // Bytes 6-11: src MAC (ignored)
                    // Bytes 12-13: EtherType
                    // ------------------------------------------
                    S_ETH_HDR: begin
                        case (byte_count)
                            8'd12: ethertype[15:8] <= byte_in;
                            8'd13: begin
                                ethertype[7:0] <= byte_in;
                                byte_count     <= 0;
                                case ({ethertype[15:8], byte_in})
                                    16'h0800: state <= S_IP_HDR;  // IPv4
                                    16'h0806: state <= S_ARP_HDR; // ARP
                                    default:  state <= S_SKIP;    // unsupported
                                endcase
                            end
                            default: byte_count <= byte_count + 1;
                        endcase
                        if (byte_count != 8'd13)
                            byte_count <= byte_count + 1;
                    end

                    // ------------------------------------------
                    // IPv4 header: minimum 20 bytes
                    // IHL field tells us actual length
                    // ------------------------------------------
                    S_IP_HDR: begin
                        case (byte_count)
                            // Byte 0: Version + IHL
                            8'd0: begin
                                // IHL is bottom 4 bits, units of 32-bit words
                                // Multiply by 4 to get byte count
                                ihl_bytes        <= {byte_in[3:0], 2'b00};
                                ip_hdr_remaining <= {byte_in[3:0], 2'b00} - 1;
                            end
                            // Byte 9: Protocol
                            8'd9: protocol <= byte_in;
                            // Bytes 12-15: Source IP
                            8'd12: src_ip[31:24] <= byte_in;
                            8'd13: src_ip[23:16] <= byte_in;
                            8'd14: src_ip[15:8]  <= byte_in;
                            8'd15: src_ip[7:0]   <= byte_in;
                            // Bytes 16-19: Destination IP
                            8'd16: dst_ip[31:24] <= byte_in;
                            8'd17: dst_ip[23:16] <= byte_in;
                            8'd18: dst_ip[15:8]  <= byte_in;
                            8'd19: begin
                                dst_ip[7:0] <= byte_in;
                                // If IHL > 5 words (20 bytes), skip options
                                // ip_hdr_remaining was set at byte 0
                                // After byte 19 we've consumed 20 bytes
                                // If ihl_bytes > 20, remaining options follow
                            end
                        endcase

                        // Transition: when we've consumed ihl_bytes bytes
                        if (byte_count == ihl_bytes - 1) begin
                            byte_count <= 0;
                            case (protocol)
                                8'h06: state <= S_TCP_HDR;
                                8'h11: state <= S_UDP_HDR;
                                default: state <= S_SKIP; // ICMP etc — no ports
                            endcase
                        end else begin
                            byte_count <= byte_count + 1;
                        end
                    end

                    // ------------------------------------------
                    // TCP header: minimum 20 bytes
                    // Data offset field gives actual length
                    // ------------------------------------------
                    S_TCP_HDR: begin
                        case (byte_count)
                            // Bytes 0-1: Source port
                            8'd0: src_port[15:8] <= byte_in;
                            8'd1: src_port[7:0]  <= byte_in;
                            // Bytes 2-3: Destination port
                            8'd2: dst_port[15:8] <= byte_in;
                            8'd3: dst_port[7:0]  <= byte_in;
                            // Byte 12: Data offset (high 4 bits) + reserved
                            8'd12: begin
                                // Data offset in 32-bit words, multiply by 4
                                tcp_data_offset_bytes <= {byte_in[7:4], 2'b00};
                                tcp_hdr_remaining     <= {byte_in[7:4], 2'b00} - 1;
                            end
                            // Byte 13: Flags
                            8'd13: begin
                                is_fin     <= byte_in[0];
                                is_syn     <= byte_in[1];
                                is_rst     <= byte_in[2];
                                is_ack     <= byte_in[4];
                                is_syn_ack <= byte_in[1] & byte_in[4]; // SYN+ACK
                            end
                        endcase

                        if (byte_count == tcp_data_offset_bytes - 1) begin
                            byte_count    <= 0;
                            hdr_valid     <= 1;  // all fields now stable
                            payload_start <= 1;
                            state         <= S_PAYLOAD;
                        end else begin
                            byte_count <= byte_count + 1;
                        end
                    end

                    // ------------------------------------------
                    // UDP header: fixed 8 bytes
                    // ------------------------------------------
                    S_UDP_HDR: begin
                        case (byte_count)
                            8'd0: src_port[15:8] <= byte_in;
                            8'd1: src_port[7:0]  <= byte_in;
                            8'd2: dst_port[15:8] <= byte_in;
                            8'd3: dst_port[7:0]  <= byte_in;
                            // Bytes 4-5: length, 6-7: checksum — ignored
                            8'd7: begin
                                hdr_valid     <= 1;
                                payload_start <= 1;
                                byte_count    <= 0;
                                state         <= S_PAYLOAD;
                            end
                        endcase
                        if (byte_count != 8'd7)
                            byte_count <= byte_count + 1;
                    end

                    // ------------------------------------------
                    // ARP header: 28 bytes for IPv4/Ethernet
                    // We only care about opcode (bytes 6-7)
                    // ------------------------------------------
                    S_ARP_HDR: begin
                        case (byte_count)
                            8'd6: ; // opcode high byte — always 0x00
                            8'd7: begin
                                is_arp_reply <= (byte_in == 8'd2);
                                hdr_valid    <= 1;
                            end
                        endcase
                        if (byte_count == 8'd27) begin
                            // ARP has no payload — wait for frame_end
                            state      <= S_SKIP;
                            byte_count <= 0;
                        end else begin
                            byte_count <= byte_count + 1;
                        end
                    end

                    // ------------------------------------------
                    // Payload forwarding: pass bytes to engines
                    // ------------------------------------------
                    S_PAYLOAD: begin
                        payload_byte  <= byte_in;
                        payload_valid <= 1;
                    end

                    // Unknown or unsupported frame type — drain silently
                    S_SKIP: begin end

                    default: state <= S_IDLE;
                endcase
            end
        end
    end

endmodule

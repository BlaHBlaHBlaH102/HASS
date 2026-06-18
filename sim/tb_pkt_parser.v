`timescale 1ns/1ps

module tb_pkt_parser;

    reg        clk         = 0;
    reg        rst_n       = 0;
    reg [7:0]  byte_in     = 0;
    reg        byte_valid  = 0;
    reg        frame_start = 0;
    reg        frame_end   = 0;

    wire [31:0] src_ip;
    wire [31:0] dst_ip;
    wire [15:0] src_port;
    wire [15:0] dst_port;
    wire [7:0]  protocol;
    wire        is_syn, is_syn_ack, is_ack, is_fin, is_rst;
    wire        is_arp_reply;
    wire [7:0]  payload_byte;
    wire        payload_valid;
    wire        payload_start;
    wire        payload_end;
    wire        hdr_valid;

    pkt_header_parser u_dut (
        .clk          (clk),
        .rst_n        (rst_n),
        .byte_in      (byte_in),
        .byte_valid   (byte_valid),
        .frame_start  (frame_start),
        .frame_end    (frame_end),
        .src_ip       (src_ip),
        .dst_ip       (dst_ip),
        .src_port     (src_port),
        .dst_port     (dst_port),
        .protocol     (protocol),
        .is_syn       (is_syn),
        .is_syn_ack   (is_syn_ack),
        .is_ack       (is_ack),
        .is_fin       (is_fin),
        .is_rst       (is_rst),
        .is_arp_reply (is_arp_reply),
        .payload_byte (payload_byte),
        .payload_valid(payload_valid),
        .payload_start(payload_start),
        .payload_end  (payload_end),
        .hdr_valid    (hdr_valid)
    );

    always #4 clk = ~clk;  // 125 MHz

    initial begin
        $dumpfile("tb_pkt_parser.vcd");
        $dumpvars(0, tb_pkt_parser);
    end

    // Task: send one byte into the parser
    task send_byte;
        input [7:0] b;
        begin
            @(posedge clk);
            byte_in    <= b;
            byte_valid <= 1;
            @(posedge clk);
            byte_valid <= 0;
        end
    endtask

    // Task: send a full frame byte array
    // We'll call this manually below for clarity
    task start_frame;
        begin
            @(posedge clk);
            frame_start <= 1;
            @(posedge clk);
            frame_start <= 0;
        end
    endtask

    task end_frame;
        begin
            @(posedge clk);
            frame_end <= 1;
            @(posedge clk);
            frame_end <= 0;
        end
    endtask

    initial begin
        // Reset
        rst_n = 0;
        repeat(4) @(posedge clk);
        rst_n = 1;
        repeat(2) @(posedge clk);

        // -------------------------------------------------------
        // TEST 1: IPv4/UDP frame
        // src_ip  = 192.168.1.10
        // dst_ip  = 8.8.8.8
        // src_port = 5000
        // dst_port = 53  (DNS)
        // -------------------------------------------------------
        $display("--- TEST 1: IPv4/UDP ---");
        start_frame;

        // Ethernet header (14 bytes)
        // Dst MAC: FF:FF:FF:FF:FF:FF
        send_byte(8'hFF); send_byte(8'hFF); send_byte(8'hFF);
        send_byte(8'hFF); send_byte(8'hFF); send_byte(8'hFF);
        // Src MAC: AA:BB:CC:DD:EE:FF
        send_byte(8'hAA); send_byte(8'hBB); send_byte(8'hCC);
        send_byte(8'hDD); send_byte(8'hEE); send_byte(8'hFF);
        // EtherType: 0x0800 (IPv4)
        send_byte(8'h08); send_byte(8'h00);

        // IPv4 header (20 bytes, IHL=5)
        send_byte(8'h45); // Version=4, IHL=5
        send_byte(8'h00); // DSCP/ECN
        send_byte(8'h00); send_byte(8'h1C); // Total length
        send_byte(8'h00); send_byte(8'h01); // ID
        send_byte(8'h00); send_byte(8'h00); // Flags/Fragment
        send_byte(8'h40); // TTL=64
        send_byte(8'h11); // Protocol=UDP (0x11)
        send_byte(8'h00); send_byte(8'h00); // Header checksum
        // src_ip = 192.168.1.10
        send_byte(8'hC0); send_byte(8'hA8); send_byte(8'h01); send_byte(8'h0A);
        // dst_ip = 8.8.8.8
        send_byte(8'h08); send_byte(8'h08); send_byte(8'h08); send_byte(8'h08);

        // UDP header (8 bytes)
        // src_port = 5000 = 0x1388
        send_byte(8'h13); send_byte(8'h88);
        // dst_port = 53 = 0x0035
        send_byte(8'h00); send_byte(8'h35);
        send_byte(8'h00); send_byte(8'h08); // length
        send_byte(8'h00); send_byte(8'h00); // checksum

        // Payload (4 bytes — dummy DNS data)
        send_byte(8'hAB); send_byte(8'hCD);
        send_byte(8'hEF); send_byte(8'h01);

        end_frame;
        repeat(4) @(posedge clk);

        // Check results
        if (src_ip == 32'hC0A8010A)
            $display("PASS: src_ip = 192.168.1.10");
        else
            $display("FAIL: src_ip = %h (expected C0A8010A)", src_ip);

        if (dst_ip == 32'h08080808)
            $display("PASS: dst_ip = 8.8.8.8");
        else
            $display("FAIL: dst_ip = %h (expected 08080808)", dst_ip);

        if (protocol == 8'h11)
            $display("PASS: protocol = UDP");
        else
            $display("FAIL: protocol = %h (expected 11)", protocol);

        if (src_port == 16'h1388)
            $display("PASS: src_port = 5000");
        else
            $display("FAIL: src_port = %h (expected 1388)", src_port);

        if (dst_port == 16'h0035)
            $display("PASS: dst_port = 53");
        else
            $display("FAIL: dst_port = %h (expected 0035)", dst_port);

        repeat(4) @(posedge clk);

        // -------------------------------------------------------
        // TEST 2: IPv4/TCP SYN frame
        // src_ip  = 10.0.0.1
        // dst_ip  = 10.0.0.2
        // src_port = 12345
        // dst_port = 80 (HTTP)
        // flags: SYN only
        // -------------------------------------------------------
        $display("--- TEST 2: IPv4/TCP SYN ---");
        start_frame;

        // Ethernet header
        send_byte(8'hFF); send_byte(8'hFF); send_byte(8'hFF);
        send_byte(8'hFF); send_byte(8'hFF); send_byte(8'hFF);
        send_byte(8'h11); send_byte(8'h22); send_byte(8'h33);
        send_byte(8'h44); send_byte(8'h55); send_byte(8'h66);
        send_byte(8'h08); send_byte(8'h00);

        // IPv4 header
        send_byte(8'h45); send_byte(8'h00);
        send_byte(8'h00); send_byte(8'h28);
        send_byte(8'h00); send_byte(8'h02);
        send_byte(8'h00); send_byte(8'h00);
        send_byte(8'h40);
        send_byte(8'h06); // Protocol=TCP
        send_byte(8'h00); send_byte(8'h00);
        // src_ip = 10.0.0.1
        send_byte(8'h0A); send_byte(8'h00); send_byte(8'h00); send_byte(8'h01);
        // dst_ip = 10.0.0.2
        send_byte(8'h0A); send_byte(8'h00); send_byte(8'h00); send_byte(8'h02);

        // TCP header (20 bytes, data offset=5)
        // src_port = 12345 = 0x3039
        send_byte(8'h30); send_byte(8'h39);
        // dst_port = 80 = 0x0050
        send_byte(8'h00); send_byte(8'h50);
        // Seq number
        send_byte(8'h00); send_byte(8'h00); send_byte(8'h00); send_byte(8'h01);
        // Ack number
        send_byte(8'h00); send_byte(8'h00); send_byte(8'h00); send_byte(8'h00);
        // Data offset=5 (0x50), reserved=0
        send_byte(8'h50); send_byte(8'h00);
        // Flags: SYN only = 0x02
        send_byte(8'h02);
        // Window
        send_byte(8'hFF); send_byte(8'hFF);
        // Checksum, urgent
        send_byte(8'h00); send_byte(8'h00);
        send_byte(8'h00); send_byte(8'h00);

        end_frame;
        repeat(4) @(posedge clk);

        if (protocol == 8'h06)
            $display("PASS: protocol = TCP");
        else
            $display("FAIL: protocol = %h (expected 06)", protocol);

        if (is_syn && !is_ack)
            $display("PASS: SYN flag set, ACK clear");
        else
            $display("FAIL: SYN=%b ACK=%b (expected SYN=1 ACK=0)", is_syn, is_ack);

        if (dst_port == 16'h0050)
            $display("PASS: dst_port = 80");
        else
            $display("FAIL: dst_port = %h (expected 0050)", dst_port);

        repeat(4) @(posedge clk);
        $display("Simulation complete.");
        $finish;
    end

endmodule
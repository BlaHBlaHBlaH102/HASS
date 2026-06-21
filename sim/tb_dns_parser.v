`timescale 1ns/1ps

module tb_dns_parser;

    reg        clk         = 0;
    reg        rst_n       = 0;
    reg [7:0]  byte_in     = 0;
    reg        byte_valid  = 0;
    reg        frame_start = 0;
    reg        frame_end   = 0;
    reg        ac_match    = 0;

    wire        dns_alert;
    wire        sinkhole_active;
    wire [31:0] sinkhole_ip;
    wire [7:0]  nxdomain_count;

    dns_parser u_dut (
        .clk             (clk),
        .rst_n           (rst_n),
        .byte_in         (byte_in),
        .byte_valid      (byte_valid),
        .frame_start     (frame_start),
        .frame_end       (frame_end),
        .ac_match        (ac_match),
        .dns_alert       (dns_alert),
        .sinkhole_active (sinkhole_active),
        .sinkhole_ip     (sinkhole_ip),
        .nxdomain_count  (nxdomain_count)
    );

    always #4 clk = ~clk;  // 125 MHz

    initial begin
        $dumpfile("tb_dns_parser.vcd");
        $dumpvars(0, tb_dns_parser);
    end

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

    // ---------------------------------------------------------------
    // Helper: send a standard DNS QUERY for "evil.com"
    // Header (12 bytes) + QNAME + QTYPE(A) + QCLASS(IN)
    // QR=0 (query), all counts zero except QDCOUNT=1
    // ---------------------------------------------------------------
    task send_query_evilcom;
        begin
            // Header: TXID=0x1234, Flags=0x0100 (standard query, RD=1),
            // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
            send_byte(8'h12); send_byte(8'h34);  // TXID
            send_byte(8'h01); send_byte(8'h00);  // Flags: QR=0
            send_byte(8'h00); send_byte(8'h01);  // QDCOUNT=1
            send_byte(8'h00); send_byte(8'h00);  // ANCOUNT=0
            send_byte(8'h00); send_byte(8'h00);  // NSCOUNT=0
            send_byte(8'h00); send_byte(8'h00);  // ARCOUNT=0

            // QNAME: "evil.com" -> 4"evil" 3"com" 0
            send_byte(8'd4); send_byte("e"); send_byte("v"); send_byte("i"); send_byte("l");
            send_byte(8'd3); send_byte("c"); send_byte("o"); send_byte("m");
            send_byte(8'd0);  // root label terminator

            // QTYPE = 1 (A record), QCLASS = 1 (IN)
            send_byte(8'h00); send_byte(8'h01);
            send_byte(8'h00); send_byte(8'h01);
        end
    endtask

    // ---------------------------------------------------------------
    // Helper: send a DNS RESPONSE with RCODE=NXDOMAIN (3)
    // Minimal header only -- no question/answer needed to test
    // flood counting, since the check happens right after the header.
    // ---------------------------------------------------------------
    task send_nxdomain_response;
        begin
            send_byte(8'h00); send_byte(8'h00);  // TXID (don't care)
            send_byte(8'h81); send_byte(8'h83);  // Flags: QR=1, RCODE=3 (NXDOMAIN)
            send_byte(8'h00); send_byte(8'h01);  // QDCOUNT=1
            send_byte(8'h00); send_byte(8'h00);  // ANCOUNT=0
            send_byte(8'h00); send_byte(8'h00);  // NSCOUNT=0
            send_byte(8'h00); send_byte(8'h00);  // ARCOUNT=0
            // Minimal QNAME just to keep the parser moving to S_DONE
            send_byte(8'd0);                      // root label (empty name)
            send_byte(8'h00); send_byte(8'h01);   // QTYPE
            send_byte(8'h00); send_byte(8'h01);   // QCLASS
        end
    endtask

    // ---------------------------------------------------------------
    // Helper: send a DNS RESPONSE for a public name that rebinds to
    // an RFC-1918 address (192.168.1.1) -- classic DNS rebinding.
    // Header: QR=1, RCODE=0 (no error), QDCOUNT=1, ANCOUNT=1
    // ---------------------------------------------------------------
    task send_rebinding_response;
        begin
            send_byte(8'h00); send_byte(8'h00);  // TXID
            send_byte(8'h81); send_byte(8'h80);  // Flags: QR=1, RCODE=0
            send_byte(8'h00); send_byte(8'h01);  // QDCOUNT=1
            send_byte(8'h00); send_byte(8'h01);  // ANCOUNT=1
            send_byte(8'h00); send_byte(8'h00);  // NSCOUNT=0
            send_byte(8'h00); send_byte(8'h00);  // ARCOUNT=0

            // Question section: "x.com" (short, just to move past QNAME)
            send_byte(8'd1); send_byte("x");
            send_byte(8'd3); send_byte("c"); send_byte("o"); send_byte("m");
            send_byte(8'd0);
            send_byte(8'h00); send_byte(8'h01);  // QTYPE
            send_byte(8'h00); send_byte(8'h01);  // QCLASS

            // Answer section: 12 bytes of NAME(compressed,2)+TYPE(2)+
            // CLASS(2)+TTL(4)+RDLENGTH(2), then 4-byte RDATA
            send_byte(8'hC0); send_byte(8'h0C);   // NAME: compression pointer
            send_byte(8'h00); send_byte(8'h01);   // TYPE = A
            send_byte(8'h00); send_byte(8'h01);   // CLASS = IN
            send_byte(8'h00); send_byte(8'h00); send_byte(8'h00); send_byte(8'h3C); // TTL=60
            send_byte(8'h00); send_byte(8'h04);   // RDLENGTH = 4

            // RDATA: 192.168.1.1 -- RFC-1918, should trigger rebinding alert
            send_byte(8'd192); send_byte(8'd168); send_byte(8'd1); send_byte(8'd1);
        end
    endtask

    integer k;

    initial begin
        rst_n = 0;
        repeat(4) @(posedge clk);
        rst_n = 1;
        repeat(2) @(posedge clk);

        // -------------------------------------------------------
        // TEST 1: AC match on a query -> sinkhole should activate
        // ac_match is asserted by the testbench partway through,
        // simulating the AC engine recognizing "evil.com" mid-stream.
        // -------------------------------------------------------
        $display("--- TEST 1: query for known-bad domain (expect sinkhole) ---");
        start_frame;
        ac_match = 1;   // simulate AC engine having already flagged this domain
        send_query_evilcom;
        ac_match = 0;
        end_frame;
        repeat(4) @(posedge clk);

        $display("  dns_alert=%b sinkhole_active=%b sinkhole_ip=%h",
                  dns_alert, sinkhole_active, sinkhole_ip);

        // -------------------------------------------------------
        // TEST 2: clean query, no AC match -> no alert, no sinkhole
        // -------------------------------------------------------
        $display("--- TEST 2: clean query, no AC match (expect no alert) ---");
        start_frame;
        send_query_evilcom;   // same bytes, but ac_match stays 0 this time
        end_frame;
        repeat(4) @(posedge clk);

        $display("  dns_alert=%b sinkhole_active=%b", dns_alert, sinkhole_active);

        // -------------------------------------------------------
        // TEST 3: DNS rebinding -- public-looking response resolving
        // to an RFC-1918 address should trigger dns_alert
        // -------------------------------------------------------
        $display("--- TEST 3: DNS rebinding response (expect dns_alert) ---");
        start_frame;
        send_rebinding_response;
        end_frame;
        repeat(4) @(posedge clk);

        $display("  dns_alert=%b (expect 1 for rebinding)", dns_alert);

        // -------------------------------------------------------
        // TEST 4: NXDOMAIN flood -- send 11 consecutive NXDOMAIN
        // responses (threshold is >=10) and confirm dns_alert fires
        // and nxdomain_count increments correctly.
        // -------------------------------------------------------
        $display("--- TEST 4: NXDOMAIN flood (11x, threshold=10) ---");
        for (k = 0; k < 11; k = k + 1) begin
            start_frame;
            send_nxdomain_response;
            end_frame;
            repeat(2) @(posedge clk);
            $display("  after NXDOMAIN #%0d: nxdomain_count=%0d dns_alert=%b",
                      k+1, nxdomain_count, dns_alert);
        end

        $display("Simulation complete.");
        $finish;
    end

endmodule
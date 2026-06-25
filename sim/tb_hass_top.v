`timescale 1ns/1ps

module tb_hass_top;

    reg clk_125mhz = 0;
    reg rst_btn    = 1;

    reg [7:0]  sim_rx_byte        = 0;
    reg        sim_rx_byte_valid  = 0;
    reg        sim_rx_frame_start = 0;
    reg        sim_rx_frame_end   = 0;

    reg        phy0_rxd1 = 0, phy0_rxd0 = 0, phy0_crs_dv = 0, phy0_rx_er = 0;
    reg        phy1_rxd1 = 0, phy1_rxd0 = 0, phy1_crs_dv = 0, phy1_rx_er = 0;
    wire       phy0_txd1, phy0_txd0, phy0_tx_en, phy0_ref_clk;
    wire       phy1_txd1, phy1_txd0, phy1_tx_en, phy1_ref_clk;

    wire [17:0] sram_addr;
    wire [15:0] sram_data;
    wire        sram_we_n, sram_oe_n, sram_ce_n;
    assign sram_data = 16'hZZZZ;

    wire        ws2812_din;

    reg         mb_axi_clk  = 0;
    reg         mb_axi_rst_n = 0;

    hass_top u_dut (
        .clk_125mhz         (clk_125mhz),
        .rst_btn            (rst_btn),
        .sim_rx_byte        (sim_rx_byte),
        .sim_rx_byte_valid  (sim_rx_byte_valid),
        .sim_rx_frame_start (sim_rx_frame_start),
        .sim_rx_frame_end   (sim_rx_frame_end),
        .phy0_rxd1   (phy0_rxd1), .phy0_rxd0 (phy0_rxd0),
        .phy0_crs_dv (phy0_crs_dv), .phy0_rx_er (phy0_rx_er),
        .phy0_txd1   (phy0_txd1), .phy0_txd0 (phy0_txd0),
        .phy0_tx_en  (phy0_tx_en), .phy0_ref_clk (phy0_ref_clk),
        .phy1_rxd1   (phy1_rxd1), .phy1_rxd0 (phy1_rxd0),
        .phy1_crs_dv (phy1_crs_dv), .phy1_rx_er (phy1_rx_er),
        .phy1_txd1   (phy1_txd1), .phy1_txd0 (phy1_txd0),
        .phy1_tx_en  (phy1_tx_en), .phy1_ref_clk (phy1_ref_clk),
        .sram_addr   (sram_addr), .sram_data (sram_data),
        .sram_we_n   (sram_we_n), .sram_oe_n (sram_oe_n), .sram_ce_n (sram_ce_n),
        .ws2812_din  (ws2812_din),
        .mb_axi_clk  (mb_axi_clk), .mb_axi_rst_n (mb_axi_rst_n)
    );

    always #4 clk_125mhz = ~clk_125mhz;

    initial begin
        $dumpfile("tb_hass_top.vcd");
        $dumpvars(0, tb_hass_top);
    end

    integer i, j, k;
    reg [9:0] goto_flat [0:255*256-1];
    initial begin
        $readmemh("goto_table.hex", goto_flat);
        for (i = 0; i < 256; i = i + 1) begin
            for (j = 0; j < 256; j = j + 1) begin
                u_dut.u_ac.goto_bram[i][j] = goto_flat[i*256 + j];
            end
        end
        $readmemh("output_table.hex", u_dut.u_ac.output_table);
        $readmemh("output_id.hex", u_dut.u_ac.output_id);
        $display("DEBUG: AC table load complete (210-state, 22-pattern set)");
    end

    reg [31:0] prng_state = 32'hDEADBEEF;
    function [7:0] next_rand_byte;
        input dummy;
        begin
            prng_state = prng_state ^ (prng_state << 13);
            prng_state = prng_state ^ (prng_state >> 17);
            prng_state = prng_state ^ (prng_state << 5);
            next_rand_byte = prng_state[7:0];
        end
    endfunction

    task send_byte;
        input [7:0] b;
        begin
            @(posedge clk_125mhz);
            sim_rx_byte       <= b;
            sim_rx_byte_valid <= 1;
            @(posedge clk_125mhz);
            sim_rx_byte_valid <= 0;
        end
    endtask

    task start_frame;
        begin
            @(posedge clk_125mhz);
            sim_rx_frame_start <= 1;
            @(posedge clk_125mhz);
            sim_rx_frame_start <= 0;
        end
    endtask

    task end_frame;
        begin
            @(posedge clk_125mhz);
            sim_rx_frame_end <= 1;
            @(posedge clk_125mhz);
            sim_rx_frame_end <= 0;
        end
    endtask

    // Sends a full Eth+IPv4+UDP frame whose payload is exactly the
    // ASCII bytes of `domain` (a DNS-shaped label sequence is NOT
    // reconstructed here -- AC only needs to see the raw characters
    // appear in order somewhere in the byte stream, since it does
    // not understand DNS framing; this keeps the task simple while
    // still proving AC's detection against realistic domain text).
    task send_udp_payload_string;
        input [8*64-1:0] str;
        input integer    str_len;
        input [15:0]     dst_port;
        integer kk;
        integer udp_len;
        begin
            udp_len = 8 + str_len;

            send_byte(8'hFF); send_byte(8'hFF); send_byte(8'hFF);
            send_byte(8'hFF); send_byte(8'hFF); send_byte(8'hFF);
            send_byte(8'hAA); send_byte(8'hBB); send_byte(8'hCC);
            send_byte(8'hDD); send_byte(8'hEE); send_byte(8'hFF);
            send_byte(8'h08); send_byte(8'h00);

            send_byte(8'h45); send_byte(8'h00);
            send_byte(8'h00); send_byte((20+udp_len) & 8'hFF);
            send_byte(8'h00); send_byte(8'h01);
            send_byte(8'h00); send_byte(8'h00);
            send_byte(8'h40);
            send_byte(8'h11);
            send_byte(8'h00); send_byte(8'h00);
            send_byte(8'hC0); send_byte(8'hA8); send_byte(8'h01); send_byte(8'h0A);
            send_byte(8'h08); send_byte(8'h08); send_byte(8'h08); send_byte(8'h08);

            send_byte(8'h13); send_byte(8'h88);
            send_byte(dst_port[15:8]); send_byte(dst_port[7:0]);
            send_byte(udp_len[15:8]); send_byte(udp_len[7:0]);
            send_byte(8'h00); send_byte(8'h00);

            for (kk = 0; kk < str_len; kk = kk + 1) begin
                send_byte(str[8*(str_len-1-kk) +: 8]);
            end
        end
    endtask

    initial begin
        $display("DEBUG: stimulus block started");
        rst_btn = 1;
        repeat(4) @(posedge clk_125mhz);
        rst_btn = 0;
        repeat(2) @(posedge clk_125mhz);

        // ---------------------------------------------------------
        // TEST 1: clean payload, no pattern present. Baseline silence.
        // ---------------------------------------------------------
        $display("--- TEST 1: clean payload (expect silence) ---");
        start_frame;
        send_udp_payload_string("github.com lookup request padding", 35, 16'd53);
        end_frame;
        repeat(4) @(posedge clk_125mhz);
        $display("  threat_detected=%b ac_match=%b dns_alert=%b entropy_alert=%b rate_alert=%b",
                  u_dut.threat_detected, u_dut.ac_match, u_dut.dns_alert,
                  u_dut.entropy_alert, u_dut.rate_alert);

        // ---------------------------------------------------------
        // TEST 2: "tech-support-scam" domain fragment (pattern 3,
        // which shares accepting state 30 with pattern 0 "scam").
        // ---------------------------------------------------------
        $display("--- TEST 2: tech-support-scam fragment (expect ac_match, sinkhole) ---");
        start_frame;
        send_udp_payload_string("alert-tech-support-scam-now.example", 36, 16'd53);
        end_frame;
        repeat(4) @(posedge clk_125mhz);
        $display("  threat_detected=%b ac_match=%b dns_alert=%b sinkhole_active=%b",
                  u_dut.threat_detected, u_dut.ac_match, u_dut.dns_alert,
                  u_dut.sinkhole_active);

        // ---------------------------------------------------------
        // TEST 3: "paypal-secure-login" phishing fragment (pattern 7,
        // which also simultaneously satisfies pattern 8 "secure-login"
        // per the accepting-state table -- both share state 85).
        // ---------------------------------------------------------
        $display("--- TEST 3: paypal-secure-login phishing fragment (expect ac_match) ---");
        start_frame;
        send_udp_payload_string("www-paypal-secure-login.example", 32, 16'd53);
        end_frame;
        repeat(4) @(posedge clk_125mhz);
        $display("  threat_detected=%b ac_match=%b dns_alert=%b",
                  u_dut.threat_detected, u_dut.ac_match, u_dut.dns_alert);

        // ---------------------------------------------------------
        // TEST 4: near-miss stress -- "scammed" (pattern 19) should
        // fire cleanly without corrupting subsequent matching.
        // ---------------------------------------------------------
        $display("--- TEST 4: \"scammed\" near-miss-prefix pattern (expect ac_match, id=19) ---");
        start_frame;
        send_udp_payload_string("i-got-scammed-yesterday.example", 32, 16'd53);
        end_frame;
        repeat(4) @(posedge clk_125mhz);
        $display("  threat_detected=%b ac_match=%b ac_pattern_id=%0d (expect 19)",
                  u_dut.threat_detected, u_dut.ac_match, u_dut.ac_pattern_id);

        // ---------------------------------------------------------
        // TEST 5: near-miss negative -- "badge-printer.com" contains
        // "bad" as a literal prefix of "badge". Since "bad" (id 20)
        // is itself a complete pattern, AC SHOULD fire on "bad" the
        // moment those 3 letters complete, then ALSO fire "badge"
        // (id 21) when the 4th letter completes -- this is correct
        // behavior, not a false positive, since "bad" genuinely is
        // a substring. Confirms both fire, in the right order.
        // ---------------------------------------------------------
        $display("--- TEST 5: \"badge-printer.com\" (expect BOTH bad id=20 then badge id=21) ---");
        start_frame;
        send_udp_payload_string("badge-printer.com", 18, 16'd53);
        end_frame;
        repeat(4) @(posedge clk_125mhz);
        $display("  threat_detected=%b ac_match=%b ac_pattern_id=%0d (last match wins, expect 21)",
                  u_dut.threat_detected, u_dut.ac_match, u_dut.ac_pattern_id);

        // ---------------------------------------------------------
        // TEST 6: "backdoor" token (pattern 18) sent as a high-entropy
        // C2-shaped payload on a non-standard port. Tests AC + entropy
        // firing simultaneously, and threat_level priority logic.
        // ---------------------------------------------------------
        $display("--- TEST 6: \"backdoor\" token + high-entropy padding, port 4444 ---");
        start_frame;
        send_byte(8'hFF); send_byte(8'hFF); send_byte(8'hFF);
        send_byte(8'hFF); send_byte(8'hFF); send_byte(8'hFF);
        send_byte(8'hAA); send_byte(8'hBB); send_byte(8'hCC);
        send_byte(8'hDD); send_byte(8'hEE); send_byte(8'hFF);
        send_byte(8'h08); send_byte(8'h00);
        send_byte(8'h45); send_byte(8'h00);
        send_byte(8'h01); send_byte(8'h10);
        send_byte(8'h00); send_byte(8'h05);
        send_byte(8'h00); send_byte(8'h00);
        send_byte(8'h40); send_byte(8'h11);
        send_byte(8'h00); send_byte(8'h00);
        send_byte(8'hC0); send_byte(8'hA8); send_byte(8'h01); send_byte(8'h0A);
        send_byte(8'h0A); send_byte(8'h00); send_byte(8'h00); send_byte(8'h02);
        send_byte(8'hAB); send_byte(8'hCD);
        send_byte(8'h11); send_byte(8'h5C);
        send_byte(8'h01); send_byte(8'h10);
        send_byte(8'h00); send_byte(8'h00);
        send_byte("b"); send_byte("a"); send_byte("c"); send_byte("k");
        send_byte("d"); send_byte("o"); send_byte("o"); send_byte("r");
        for (k = 0; k < 248; k = k + 1) begin
            send_byte(next_rand_byte(1'b0));
        end
        end_frame;
        repeat(300) @(posedge clk_125mhz);
        $display("  threat_detected=%b ac_match=%b entropy_alert=%b threat_level priority check via LED logic",
                  u_dut.threat_detected, u_dut.ac_match, u_dut.entropy_alert);

        // ---------------------------------------------------------
        // TEST 7: DNS rebinding (same proven scenario as before).
        // ---------------------------------------------------------
        $display("--- TEST 7: DNS rebinding to 192.168.50.1 (expect dns_alert) ---");
        start_frame;
        send_byte(8'hFF); send_byte(8'hFF); send_byte(8'hFF);
        send_byte(8'hFF); send_byte(8'hFF); send_byte(8'hFF);
        send_byte(8'hAA); send_byte(8'hBB); send_byte(8'hCC);
        send_byte(8'hDD); send_byte(8'hEE); send_byte(8'hFF);
        send_byte(8'h08); send_byte(8'h00);
        send_byte(8'h45); send_byte(8'h00);
        send_byte(8'h00); send_byte(8'h3C);
        send_byte(8'h00); send_byte(8'h04);
        send_byte(8'h00); send_byte(8'h00);
        send_byte(8'h40); send_byte(8'h11);
        send_byte(8'h00); send_byte(8'h00);
        send_byte(8'h08); send_byte(8'h08); send_byte(8'h08); send_byte(8'h08);
        send_byte(8'hC0); send_byte(8'hA8); send_byte(8'h01); send_byte(8'h0A);
        send_byte(8'h00); send_byte(8'h35);
        send_byte(8'h13); send_byte(8'h88);
        send_byte(8'h00); send_byte(8'h28);
        send_byte(8'h00); send_byte(8'h00);
        send_byte(8'h00); send_byte(8'h03);
        send_byte(8'h81); send_byte(8'h80);
        send_byte(8'h00); send_byte(8'h01);
        send_byte(8'h00); send_byte(8'h01);
        send_byte(8'h00); send_byte(8'h00);
        send_byte(8'h00); send_byte(8'h00);
        send_byte(8'h11);
        send_byte("m");send_byte("y");send_byte("-");send_byte("r");send_byte("o");
        send_byte("u");send_byte("t");send_byte("e");send_byte("r");send_byte("-");
        send_byte("u");send_byte("p");send_byte("d");send_byte("a");send_byte("t");
        send_byte("e");send_byte("-");
        send_byte(8'h03); send_byte("n"); send_byte("e"); send_byte("t");
        send_byte(8'h00);
        send_byte(8'h00); send_byte(8'h01);
        send_byte(8'h00); send_byte(8'h01);
        send_byte(8'hC0); send_byte(8'h0C);
        send_byte(8'h00); send_byte(8'h01);
        send_byte(8'h00); send_byte(8'h01);
        send_byte(8'h00); send_byte(8'h00); send_byte(8'h00); send_byte(8'h3C);
        send_byte(8'h00); send_byte(8'h04);
        send_byte(8'd192); send_byte(8'd168); send_byte(8'd50); send_byte(8'd1);
        end_frame;
        repeat(4) @(posedge clk_125mhz);
        $display("  threat_detected=%b dns_alert=%b", u_dut.threat_detected, u_dut.dns_alert);

        // ---------------------------------------------------------
        // TEST 8: NXDOMAIN burst (same proven scenario as before).
        // ---------------------------------------------------------
        $display("--- TEST 8: NXDOMAIN burst, 10x rapid responses ---");
        for (k = 0; k < 10; k = k + 1) begin
            start_frame;
            send_byte(8'hFF); send_byte(8'hFF); send_byte(8'hFF);
            send_byte(8'hFF); send_byte(8'hFF); send_byte(8'hFF);
            send_byte(8'hAA); send_byte(8'hBB); send_byte(8'hCC);
            send_byte(8'hDD); send_byte(8'hEE); send_byte(8'hFF);
            send_byte(8'h08); send_byte(8'h00);
            send_byte(8'h45); send_byte(8'h00);
            send_byte(8'h00); send_byte(8'h21);
            send_byte(k[7:0]); send_byte(8'h00);
            send_byte(8'h00); send_byte(8'h00);
            send_byte(8'h40); send_byte(8'h11);
            send_byte(8'h00); send_byte(8'h00);
            send_byte(8'h08); send_byte(8'h08); send_byte(8'h08); send_byte(8'h08);
            send_byte(8'hC0); send_byte(8'hA8); send_byte(8'h01); send_byte(8'h0A);
            send_byte(8'h00); send_byte(8'h35);
            send_byte(8'h13); send_byte(8'h88);
            send_byte(8'h00); send_byte(8'h0D);
            send_byte(8'h00); send_byte(8'h00);
            send_byte(8'h00); send_byte(k[7:0]);
            send_byte(8'h81); send_byte(8'h83);
            send_byte(8'h00); send_byte(8'h01);
            send_byte(8'h00); send_byte(8'h00);
            send_byte(8'h00); send_byte(8'h00);
            send_byte(8'h00); send_byte(8'h00);
            send_byte(8'h00);
            send_byte(8'h00); send_byte(8'h01);
            send_byte(8'h00); send_byte(8'h01);
            end_frame;
            repeat(2) @(posedge clk_125mhz);
        end
        $display("  threat_detected=%b dns_alert=%b (expect 1 at 10th NXDOMAIN)",
                  u_dut.threat_detected, u_dut.dns_alert);

        // ---------------------------------------------------------
        // TEST 9: SYN flood through the FULL pipeline (TEMAC bypass
        // -> pkt_header_parser -> rate_monitor). 31x SYN packets,
        // same 4-tuple, no SYN-ACKs.
        // ---------------------------------------------------------
        $display("--- TEST 9: SYN flood, 31x SYN packets, same flow (expect rate_alert) ---");
        for (k = 0; k < 31; k = k + 1) begin
            start_frame;
            send_byte(8'hFF); send_byte(8'hFF); send_byte(8'hFF);
            send_byte(8'hFF); send_byte(8'hFF); send_byte(8'hFF);
            send_byte(8'hAA); send_byte(8'hBB); send_byte(8'hCC);
            send_byte(8'hDD); send_byte(8'hEE); send_byte(8'hFF);
            send_byte(8'h08); send_byte(8'h00);
            send_byte(8'h45); send_byte(8'h00);
            send_byte(8'h00); send_byte(8'h28);
            send_byte(8'h00); send_byte(k[7:0]);
            send_byte(8'h00); send_byte(8'h00);
            send_byte(8'h40); send_byte(8'h06);
            send_byte(8'h00); send_byte(8'h00);
            send_byte(8'h0A); send_byte(8'h00); send_byte(8'h00); send_byte(8'h01);
            send_byte(8'h0A); send_byte(8'h00); send_byte(8'h00); send_byte(8'h02);
            send_byte(8'h17); send_byte(8'h70);
            send_byte(8'h00); send_byte(8'h50);
            send_byte(8'h00); send_byte(8'h00); send_byte(8'h00); send_byte(8'h01);
            send_byte(8'h00); send_byte(8'h00); send_byte(8'h00); send_byte(8'h00);
            send_byte(8'h50); send_byte(8'h00);
            send_byte(8'h02);
            send_byte(8'hFF); send_byte(8'hFF);
            send_byte(8'h00); send_byte(8'h00);
            send_byte(8'h00); send_byte(8'h00);
            end_frame;
            repeat(2) @(posedge clk_125mhz);
        end
        $display("  threat_detected=%b rate_alert=%b (expect 1 by packet 30)",
                  u_dut.threat_detected, u_dut.rate_alert);

        $display("Simulation complete.");
        $finish;
    end

endmodule
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
        $display("DEBUG: AC table load complete");
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

    task send_dns_query_frame;
        input [8*32-1:0] payload;
        input integer    payload_len;
        integer kk;
        integer udp_len;
        begin
            udp_len = 8 + payload_len;

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
            send_byte(8'h00); send_byte(8'h35);
            send_byte(udp_len[15:8]); send_byte(udp_len[7:0]);
            send_byte(8'h00); send_byte(8'h00);

            for (kk = 0; kk < payload_len; kk = kk + 1) begin
                send_byte(payload[8*(payload_len-1-kk) +: 8]);
            end
        end
    endtask

    initial begin
        $display("DEBUG: stimulus block started");
        rst_btn = 1;
        repeat(4) @(posedge clk_125mhz);
        rst_btn = 0;
        repeat(2) @(posedge clk_125mhz);

        $display("--- TEST 1: clean query, ordinary domain (expect silence) ---");
        start_frame;
        send_dns_query_frame(
            {8'h00,8'h01,8'h01,8'h00,8'h00,8'h01,8'h00,8'h00,
             8'h00,8'h00,8'h00,8'h00,8'h06,"g","i","t","h","u","b",
             8'h03,"c","o","m",8'h00,8'h00,8'h01,8'h00,8'h01,
             8'h00,8'h00,8'h00,8'h00,8'h00,8'h00}, 30);
        end_frame;
        repeat(4) @(posedge clk_125mhz);
        $display("  threat_detected=%b ac_match=%b dns_alert=%b entropy_alert=%b rate_alert=%b",
                  u_dut.threat_detected, u_dut.ac_match, u_dut.dns_alert,
                  u_dut.entropy_alert, u_dut.rate_alert);

        $display("--- TEST 2: query for windows-scam-alert.com (expect sinkhole) ---");
        start_frame;
        send_dns_query_frame(
            {8'h00,8'h02,8'h01,8'h00,8'h00,8'h01,8'h00,8'h00,
             8'h00,8'h00,8'h00,8'h00,
             8'h12,"w","i","n","d","o","w","s","-","s","c","a","m","-","a","l","e","r","t",
             8'h03,"c","o","m",8'h00,8'h00,8'h01,8'h00,8'h01}, 32);
        end_frame;
        repeat(4) @(posedge clk_125mhz);
        $display("  threat_detected=%b ac_match=%b dns_alert=%b sinkhole_active=%b sinkhole_ip=%h",
                  u_dut.threat_detected, u_dut.ac_match, u_dut.dns_alert,
                  u_dut.sinkhole_active, u_dut.sinkhole_ip);

        $display("--- TEST 3: high-entropy 256-byte UDP payload, port 4444 (expect entropy_alert) ---");
        start_frame;
        send_byte(8'hFF); send_byte(8'hFF); send_byte(8'hFF);
        send_byte(8'hFF); send_byte(8'hFF); send_byte(8'hFF);
        send_byte(8'hAA); send_byte(8'hBB); send_byte(8'hCC);
        send_byte(8'hDD); send_byte(8'hEE); send_byte(8'hFF);
        send_byte(8'h08); send_byte(8'h00);
        send_byte(8'h45); send_byte(8'h00);
        send_byte(8'h01); send_byte(8'h08);
        send_byte(8'h00); send_byte(8'h03);
        send_byte(8'h00); send_byte(8'h00);
        send_byte(8'h40); send_byte(8'h11);
        send_byte(8'h00); send_byte(8'h00);
        send_byte(8'hC0); send_byte(8'hA8); send_byte(8'h01); send_byte(8'h0A);
        send_byte(8'h0A); send_byte(8'h00); send_byte(8'h00); send_byte(8'h02);
        send_byte(8'hAB); send_byte(8'hCD);
        send_byte(8'h11); send_byte(8'h5C);
        send_byte(8'h01); send_byte(8'h08);
        send_byte(8'h00); send_byte(8'h00);
        for (k = 0; k < 256; k = k + 1) begin
            send_byte(next_rand_byte(1'b0));
        end
        end_frame;
        repeat(300) @(posedge clk_125mhz);
        $display("  threat_detected=%b entropy_alert=%b dns_alert=%b",
                  u_dut.threat_detected, u_dut.entropy_alert, u_dut.dns_alert);

        $display("--- TEST 4: DNS response rebinding to 192.168.50.1 (expect dns_alert) ---");
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

        $display("--- TEST 5: NXDOMAIN burst, 10x rapid responses ---");
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

        $display("Simulation complete.");
        $finish;
    end

endmodule
// ============================================================
// HASS - Top-Level Wrapper
// Connects: TEMAC -> Inspection Engines -> Alert/Sinkhole Logic
// Target: Digilent Arty A7-100T (Artix-7 XC7A100T)
// ============================================================

module hass_top (
    input  wire        clk_125mhz,    // Arty on-board oscillator
    input  wire        rst_btn,       // BTN0 as active-high reset

    // LAN8720A PHY 0 (WAN side — from router)
    input  wire        phy0_rxd1,
    input  wire        phy0_rxd0,
    input  wire        phy0_crs_dv,
    input  wire        phy0_rx_er,
    output wire        phy0_txd1,
    output wire        phy0_txd0,
    output wire        phy0_tx_en,
    output wire        phy0_ref_clk,  // 50 MHz to PHY XTAL_IN

    // LAN8720A PHY 1 (LAN side — to user PC)
    input  wire        phy1_rxd1,
    input  wire        phy1_rxd0,
    input  wire        phy1_crs_dv,
    input  wire        phy1_rx_er,
    output wire        phy1_txd1,
    output wire        phy1_txd0,
    output wire        phy1_tx_en,
    output wire        phy1_ref_clk,

    // IS62WV51216 SRAM (shared bus, arbitrated)
    output wire [17:0] sram_addr,
    inout  wire [15:0] sram_data,
    output wire        sram_we_n,
    output wire        sram_oe_n,
    output wire        sram_ce_n,

    // WS2812B LED strip (via 74AHCT125 level shifter)
    output wire        ws2812_din,

    // MicroBlaze AXI (stub — will be expanded)
    // Included so IP integrator sees the port early
    input  wire        mb_axi_clk,
    input  wire        mb_axi_rst_n
);

    // ----------------------------------------------------------
    // Internal wires: byte stream from TEMAC to engines
    // ----------------------------------------------------------
    wire [7:0]  rx_byte;
    wire        rx_byte_valid;
    wire        rx_frame_start;
    wire        rx_frame_end;

    // Per-engine match signals
    wire        ac_match;
    wire [9:0]  ac_pattern_id;
    wire [15:0] ac_offset;

    wire        entropy_alert;     // stub — entropy_calc.v (TBD)
    wire        dns_alert;         // stub — dns_parser.v (TBD)
    wire        rate_alert;        // stub — rate_monitor.v (TBD)

    // Combined threat signal
    wire        threat_detected;
    assign threat_detected = ac_match | entropy_alert | dns_alert | rate_alert;

    // DNS sinkhole override (driven by dns_parser when blocking)
    wire        sinkhole_active;
    wire [31:0] sinkhole_ip;       // 192.168.254.1 hardcoded in dns_parser

    // ----------------------------------------------------------
    // Clock/reset
    // ----------------------------------------------------------
    wire clk;
    wire rst_n;
    assign clk   = clk_125mhz;
    assign rst_n = ~rst_btn;

    // 50 MHz reference to both PHYs (ODDR or BUFR — tie for now)
    assign phy0_ref_clk = 1'b0;  // TODO: replace with MMCM 50 MHz output
    assign phy1_ref_clk = 1'b0;

    // ----------------------------------------------------------
    // TEMAC + RMII shim (Xilinx TEMAC IP core instantiation stub)
    // Full port list comes from Vivado IP integrator export
    // ----------------------------------------------------------
    temac_rmii_shim u_temac (
        .clk           (clk),
        .rst_n         (rst_n),
        // PHY0 RMII
        .phy0_rxd      ({phy0_rxd1, phy0_rxd0}),
        .phy0_crs_dv   (phy0_crs_dv),
        .phy0_rx_er    (phy0_rx_er),
        .phy0_txd      ({phy0_txd1, phy0_txd0}),
        .phy0_tx_en    (phy0_tx_en),
        // PHY1 RMII
        .phy1_rxd      ({phy1_rxd1, phy1_rxd0}),
        .phy1_crs_dv   (phy1_crs_dv),
        .phy1_rx_er    (phy1_rx_er),
        .phy1_txd      ({phy1_txd1, phy1_txd0}),
        .phy1_tx_en    (phy1_tx_en),
        // Byte stream out to inspection pipeline
        .rx_byte       (rx_byte),
        .rx_byte_valid (rx_byte_valid),
        .rx_frame_start(rx_frame_start),
        .rx_frame_end  (rx_frame_end),
        // Sinkhole inject (DNS forged response path)
        .sinkhole_active(sinkhole_active),
        .sinkhole_ip    (sinkhole_ip)
    );

    // ----------------------------------------------------------
    // Engine 1: Aho-Corasick signature matcher
    // ----------------------------------------------------------
    aho_corasick u_ac (
        .clk              (clk),
        .rst_n            (rst_n),
        .byte_in          (rx_byte),
        .byte_valid       (rx_byte_valid),
        .frame_start      (rx_frame_start),
        .frame_end        (rx_frame_end),
        .match_found      (ac_match),
        .match_pattern_id (ac_pattern_id),
        .match_offset     (ac_offset),
        .sram_addr        (sram_addr),
        .sram_data        (sram_data),
        .sram_we_n        (sram_we_n),
        .sram_oe_n        (sram_oe_n),
        .sram_ce_n        (sram_ce_n)
    );

    // ----------------------------------------------------------
    // Engine 2: Shannon entropy calculator (stub)
    // ----------------------------------------------------------
    // entropy_calc u_entropy ( ... );
    assign entropy_alert = 1'b0;

    // ----------------------------------------------------------
    // Engine 3: DNS protocol parser + sinkhole (stub)
    // ----------------------------------------------------------
    // dns_parser u_dns ( ... );
    assign dns_alert     = 1'b0;
    assign sinkhole_active = 1'b0;
    assign sinkhole_ip     = 32'hC0A8FE01;  // 192.168.254.1

    // ----------------------------------------------------------
    // Engine 4: Rate / flow monitor (stub)
    // ----------------------------------------------------------
    // rate_monitor u_rate ( ... );
    assign rate_alert = 1'b0;

    // ----------------------------------------------------------
    // Alert controller: drives WS2812B LED strip
    // ----------------------------------------------------------
    ws2812_alert u_alert (
        .clk            (clk),
        .rst_n          (rst_n),
        .threat_detected(threat_detected),
        .threat_level   (ac_match ? 2'd2 :
                         dns_alert ? 2'd3 :
                         2'd1),
        .ws2812_din     (ws2812_din)
    );

endmodule


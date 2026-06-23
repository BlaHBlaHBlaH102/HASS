// ============================================================
// HASS - Top-Level Wrapper
// Connects: TEMAC -> Header Parser -> Inspection Engines -> Alert/Sinkhole Logic
// Target: Digilent Arty A7-100T (Artix-7 XC7A100T)
// ============================================================

module hass_top (
    input  wire        clk_125mhz,
    input  wire        rst_btn,

`ifdef SIM_BYPASS_TEMAC
    input  wire [7:0]  sim_rx_byte,
    input  wire        sim_rx_byte_valid,
    input  wire        sim_rx_frame_start,
    input  wire        sim_rx_frame_end,
`endif

    input  wire        phy0_rxd1,
    input  wire        phy0_rxd0,
    input  wire        phy0_crs_dv,
    input  wire        phy0_rx_er,
    output wire        phy0_txd1,
    output wire        phy0_txd0,
    output wire        phy0_tx_en,
    output wire        phy0_ref_clk,

    input  wire        phy1_rxd1,
    input  wire        phy1_rxd0,
    input  wire        phy1_crs_dv,
    input  wire        phy1_rx_er,
    output wire        phy1_txd1,
    output wire        phy1_txd0,
    output wire        phy1_tx_en,
    output wire        phy1_ref_clk,

    output wire [17:0] sram_addr,
    inout  wire [15:0] sram_data,
    output wire        sram_we_n,
    output wire        sram_oe_n,
    output wire        sram_ce_n,

    output wire        ws2812_din,

    input  wire        mb_axi_clk,
    input  wire        mb_axi_rst_n
);

`ifdef SIM_BYPASS_TEMAC
    wire [7:0]  rx_byte        = sim_rx_byte;
    wire        rx_byte_valid  = sim_rx_byte_valid;
    wire        rx_frame_start = sim_rx_frame_start;
    wire        rx_frame_end   = sim_rx_frame_end;
`else
    wire [7:0]  rx_byte;
    wire        rx_byte_valid;
    wire        rx_frame_start;
    wire        rx_frame_end;
`endif

    wire [31:0] hdr_src_ip;
    wire [31:0] hdr_dst_ip;
    wire [15:0] hdr_src_port;
    wire [15:0] hdr_dst_port;
    wire [7:0]  hdr_protocol;
    wire        hdr_is_syn;
    wire        hdr_is_syn_ack;
    wire        hdr_is_ack;
    wire        hdr_is_fin;
    wire        hdr_is_rst;
    wire        hdr_is_arp_reply;
    wire [7:0]  hdr_payload_byte;
    wire        hdr_payload_valid;
    wire        hdr_payload_start;
    wire        hdr_payload_end;
    wire        hdr_valid;

    wire dns_is_udp53 = (hdr_protocol == 8'h11) &&
                        ((hdr_src_port == 16'd53) || (hdr_dst_port == 16'd53));
    wire dns_byte_valid = hdr_payload_valid && dns_is_udp53;

    wire        ac_match;
    wire [9:0]  ac_pattern_id;
    wire [15:0] ac_offset;

    wire        entropy_alert;
    wire        dns_alert;
    wire        rate_alert;
    wire [1:0]  rate_alert_type;
    wire [7:0]  dns_nxdomain_count;

    wire        threat_detected;
    assign threat_detected = ac_match | entropy_alert | dns_alert | rate_alert;

    wire        sinkhole_active;
    wire [31:0] sinkhole_ip;

    wire clk;
    wire rst_n;
    assign clk   = clk_125mhz;
    assign rst_n = ~rst_btn;

    assign phy0_ref_clk = 1'b0;
    assign phy1_ref_clk = 1'b0;

    /*
    temac_rmii_shim u_temac (
        .clk           (clk),
        .rst_n         (rst_n),
        .phy0_rxd      ({phy0_rxd1, phy0_rxd0}),
        .phy0_crs_dv   (phy0_crs_dv),
        .phy0_rx_er    (phy0_rx_er),
        .phy0_txd      ({phy0_txd1, phy0_txd0}),
        .phy0_tx_en    (phy0_tx_en),
        .phy1_rxd      ({phy1_rxd1, phy1_rxd0}),
        .phy1_crs_dv   (phy1_crs_dv),
        .phy1_rx_er    (phy1_rx_er),
        .phy1_txd      ({phy1_txd1, phy1_txd0}),
        .phy1_tx_en    (phy1_tx_en),
        .rx_byte       (rx_byte),
        .rx_byte_valid (rx_byte_valid),
        .rx_frame_start(rx_frame_start),
        .rx_frame_end  (rx_frame_end),
        .sinkhole_active(sinkhole_active),
        .sinkhole_ip    (sinkhole_ip)
    );
    */

    pkt_header_parser u_pkt_parser (
        .clk           (clk),
        .rst_n         (rst_n),
        .byte_in       (rx_byte),
        .byte_valid    (rx_byte_valid),
        .frame_start   (rx_frame_start),
        .frame_end     (rx_frame_end),
        .src_ip        (hdr_src_ip),
        .dst_ip        (hdr_dst_ip),
        .src_port      (hdr_src_port),
        .dst_port      (hdr_dst_port),
        .protocol      (hdr_protocol),
        .is_syn        (hdr_is_syn),
        .is_syn_ack    (hdr_is_syn_ack),
        .is_ack        (hdr_is_ack),
        .is_fin        (hdr_is_fin),
        .is_rst        (hdr_is_rst),
        .is_arp_reply  (hdr_is_arp_reply),
        .payload_byte  (hdr_payload_byte),
        .payload_valid (hdr_payload_valid),
        .payload_start (hdr_payload_start),
        .payload_end   (hdr_payload_end),
        .hdr_valid     (hdr_valid)
    );

    aho_corasick u_ac (
        .clk              (clk),
        .rst_n            (rst_n),
        .byte_in          (hdr_payload_byte),
        .byte_valid       (hdr_payload_valid),
        .frame_start      (hdr_payload_start),
        .frame_end        (hdr_payload_end),
        .match_found      (ac_match),
        .match_pattern_id (ac_pattern_id),
        .match_offset     (ac_offset),
        .sram_addr        (sram_addr),
        .sram_data        (sram_data),
        .sram_we_n        (sram_we_n),
        .sram_oe_n        (sram_oe_n),
        .sram_ce_n        (sram_ce_n)
    );

    entropy_calc u_entropy (
        .clk           (clk),
        .rst_n         (rst_n),
        .byte_in       (hdr_payload_byte),
        .byte_valid    (hdr_payload_valid),
        .frame_start   (hdr_payload_start),
        .frame_end     (hdr_payload_end),
        .entropy_alert (entropy_alert),
        .entropy_value ()
    );

    dns_parser u_dns (
        .clk             (clk),
        .rst_n           (rst_n),
        .byte_in         (hdr_payload_byte),
        .byte_valid      (dns_byte_valid),
        .frame_start     (hdr_payload_start),
        .frame_end       (hdr_payload_end),
        .ac_match        (ac_match),
        .dns_alert       (dns_alert),
        .sinkhole_active (sinkhole_active),
        .sinkhole_ip     (sinkhole_ip),
        .nxdomain_count  (dns_nxdomain_count)
    );

    rate_monitor u_rate (
        .clk          (clk),
        .rst_n        (rst_n),
        .src_ip       (hdr_src_ip),
        .dst_ip       (hdr_dst_ip),
        .src_port     (hdr_src_port),
        .dst_port     (hdr_dst_port),
        .protocol     (hdr_protocol),
        .pkt_valid    (hdr_valid),
        .is_syn       (hdr_is_syn),
        .is_syn_ack   (hdr_is_syn_ack),
        .is_arp_reply (hdr_is_arp_reply),
        .rate_alert   (rate_alert),
        .alert_type   (rate_alert_type)
    );

    ws2812_alert u_alert (
        .clk            (clk),
        .rst_n          (rst_n),
        .threat_detected(threat_detected),
        .threat_level   ((ac_match || dns_alert) ? 2'd2 :
                          (entropy_alert || rate_alert) ? 2'd1 :
                          2'd0),
        .ws2812_din     (ws2812_din)
    );

endmodule
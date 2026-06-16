`timescale 1ns/1ps

module tb_ws2812;

    reg clk   = 0;
    reg rst_n = 0;
    reg threat_detected = 0;
    reg [1:0] threat_level = 0;
    reg packet_dropped = 0;

    wire ws2812_din;

    // Instantiate the DUT
    ws2812_alert #(
        .CLK_MHZ  (125),
        .NUM_LEDS (8)
    ) u_dut (
        .clk            (clk),
        .rst_n          (rst_n),
        .threat_detected(threat_detected),
        .threat_level   (threat_level),
        .packet_dropped (packet_dropped),
        .ws2812_din     (ws2812_din)
    );

    // 125 MHz clock
    always #4 clk = ~clk;

    // VCD dump so GTKWave can open it
    initial begin
        $dumpfile("tb_ws2812.vcd");
        $dumpvars(0, tb_ws2812);
    end

    initial begin
        // Release reset after a few cycles
        rst_n = 0;
        repeat(4) @(posedge clk);
        rst_n = 1;

        // --- Test 1: SAFE state (green) ---
        threat_level = 2'd0;
        threat_detected = 0;
        $display("Testing SAFE state (green)...");
        repeat(50000) @(posedge clk);

        // --- Test 2: SUSPICIOUS state (yellow breathing) ---
        threat_level = 2'd1;
        threat_detected = 1;
        $display("Testing SUSPICIOUS state (yellow breathing)...");
        repeat(50000) @(posedge clk);

        // --- Test 3: MALICIOUS state (red flash) ---
        threat_level = 2'd2;
        $display("Testing MALICIOUS state (red flash)...");
        repeat(50000) @(posedge clk);

        // Simulate a packet drop pulse
        packet_dropped = 1;
        @(posedge clk);
        packet_dropped = 0;
        repeat(50000) @(posedge clk);

        $display("Simulation complete.");
        $finish;
    end

endmodule
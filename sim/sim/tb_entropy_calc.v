`timescale 1ns/1ps

module tb_entropy_calc;

    reg        clk         = 0;
    reg        rst_n       = 0;
    reg [7:0]  byte_in     = 0;
    reg        byte_valid  = 0;
    reg        frame_start = 0;
    reg        frame_end   = 0;

    wire        entropy_alert;
    wire [15:0] entropy_value;

    entropy_calc u_dut (
        .clk           (clk),
        .rst_n         (rst_n),
        .byte_in       (byte_in),
        .byte_valid    (byte_valid),
        .frame_start   (frame_start),
        .frame_end     (frame_end),
        .entropy_alert (entropy_alert),
        .entropy_value (entropy_value)
    );

    always #4 clk = ~clk;  // 125 MHz

    initial begin
        $display("DEBUG: stimulus block started");
        $dumpfile("tb_entropy_calc.vcd");
        $dumpvars(0, tb_entropy_calc);
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

    integer k;

    initial begin
        $display("DEBUG: stimulus block started");
        rst_n = 0;
        repeat(4) @(posedge clk);
        rst_n = 1;
        repeat(2) @(posedge clk);

        // -------------------------------------------------------
        // TEST 1: zero entropy -- 256 identical bytes (0x41 'A')
        // Expected H ~= 0.0  =>  entropy_value ~= 0
        // -------------------------------------------------------
        $display("--- TEST 1: 256x identical bytes (expect H ~ 0) ---");
        @(posedge clk); frame_start <= 1; @(posedge clk); frame_start <= 0;
        for (k = 0; k < 256; k = k + 1) begin
            send_byte(8'h41);
        end
        // window_done fires internally after the 256th byte;
        // give the accumulator FSM time to walk all 256 bins
        repeat(300) @(posedge clk);

        $display("  entropy_value = %0d (Q9.7, i.e. %0d.%0d bits/byte)",
                  entropy_value, entropy_value >> 7,
                  ((entropy_value & 7'h7F) * 100) / 128);
        $display("  entropy_alert = %b", entropy_alert);

        @(posedge clk); frame_end <= 1; @(posedge clk); frame_end <= 0;
        repeat(4) @(posedge clk);

        // -------------------------------------------------------
        // TEST 2: max entropy -- 256 distinct bytes, 0x00..0xFF
        // Expected H ~= 8.0  =>  entropy_value ~= 8*128 = 1024
        // This should trip entropy_alert (threshold ~7.0 = 0xE000>>8=896... 
        // wait: ALERT_THRESH is compared directly to entropy_sum[23:8],
        // which IS entropy_value, so threshold is 16'hE000 truncated --
        // actually ALERT_THRESH is a 16-bit literal compared against
        // a value that's only ever going to be ~0-1024 (Q9.7), so let's
        // just observe what the DUT reports and sanity-check it.
        // -------------------------------------------------------
        $display("--- TEST 2: 256 distinct bytes 0x00-0xFF (expect H ~ 8.0) ---");
        @(posedge clk); frame_start <= 1; @(posedge clk); frame_start <= 0;
        for (k = 0; k < 256; k = k + 1) begin
            send_byte(k[7:0]);
        end
        repeat(300) @(posedge clk);

        $display("  entropy_value = %0d (Q9.7, i.e. %0d.%0d bits/byte)",
                  entropy_value, entropy_value >> 7,
                  ((entropy_value & 7'h7F) * 100) / 128);
        $display("  entropy_alert = %b", entropy_alert);

        @(posedge clk); frame_end <= 1; @(posedge clk); frame_end <= 0;
        repeat(4) @(posedge clk);

        // -------------------------------------------------------
        // TEST 3: mid-range -- alternating two bytes (low entropy,
        // but not zero -- should read close to 1.0 bit/byte)
        // -------------------------------------------------------
        $display("--- TEST 3: alternating 0x00/0xFF (expect H ~ 1.0) ---");
        @(posedge clk); frame_start <= 1; @(posedge clk); frame_start <= 0;
        for (k = 0; k < 256; k = k + 1) begin
            send_byte(k[0] ? 8'h00 : 8'hFF);
        end
        repeat(300) @(posedge clk);

        $display("  entropy_value = %0d (Q9.7, i.e. %0d.%0d bits/byte)",
                  entropy_value, entropy_value >> 7,
                  ((entropy_value & 7'h7F) * 100) / 128);
        $display("  entropy_alert = %b", entropy_alert);

        @(posedge clk); frame_end <= 1; @(posedge clk); frame_end <= 0;
        repeat(4) @(posedge clk);

        $display("Simulation complete.");
        $finish;
    end

endmodule
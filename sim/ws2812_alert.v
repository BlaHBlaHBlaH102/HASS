// ============================================================
// HASS - WS2812B Alert LED Driver
// Behaviors:
//   SAFE     : steady green
//   SUSPICIOUS: yellow breathing (fades in/out)
//   MALICIOUS : red flash, clears when packet dropped
// Target: Artix-7 @ 125 MHz (8ns per clock)
// ============================================================

module ws2812_alert #(
    parameter CLK_MHZ    = 125,   // system clock frequency
    parameter NUM_LEDS   = 8      // number of LEDs in strip
)(
    input  wire        clk,
    input  wire        rst_n,

    // From threat aggregator in hass_top
    input  wire        threat_detected,
    input  wire [1:0]  threat_level,   // 0=safe, 1=suspicious, 2=malicious
    input  wire        packet_dropped, // pulse: malicious packet was dropped

    // To 74AHCT125 level shifter -> WS2812B DIN
    output reg         ws2812_din
);

    // ----------------------------------------------------------
    // WS2812B timing constants @ 125 MHz (all in clock cycles)
    // T1H = 800ns, T1L = 450ns
    // T0H = 400ns, T0L = 850ns
    // RES = 60us (safe margin over 50us minimum)
    // ----------------------------------------------------------
    localparam T1H  = (CLK_MHZ * 800)  / 1000;   // 100 cycles
    localparam T1L  = (CLK_MHZ * 450)  / 1000;   //  56 cycles
    localparam T0H  = (CLK_MHZ * 400)  / 1000;   //  50 cycles
    localparam T0L  = (CLK_MHZ * 850)  / 1000;   // 106 cycles
    localparam TRESET = CLK_MHZ * 60;             // 7500 cycles

    // ----------------------------------------------------------
    // Threat level encoding
    // ----------------------------------------------------------
    localparam SAFE       = 2'd0;
    localparam SUSPICIOUS = 2'd1;
    localparam MALICIOUS  = 2'd2;

    // ----------------------------------------------------------
    // Breathing effect: 8-bit brightness counter
    // Cycles through 0->255->0 at ~2Hz for yellow breathing
    // At 125 MHz, 2Hz period = 62,500,000 cycles
    // Half period (0->255 ramp) = 62,500,000 / 2 = 31,250,000
    // Step every 31,250,000 / 255 = ~122,549 cycles
    // ----------------------------------------------------------
    localparam BREATH_STEP_CYCLES = 122549;

    reg [16:0] breath_counter;
    reg [7:0]  brightness;        // 0-255
    reg        breath_dir;        // 0=rising, 1=falling

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            breath_counter <= 0;
            brightness     <= 8'd0;
            breath_dir     <= 0;
        end else begin
            if (breath_counter >= BREATH_STEP_CYCLES - 1) begin
                breath_counter <= 0;
                if (!breath_dir) begin
                    if (brightness == 8'd255) breath_dir <= 1;
                    else                      brightness <= brightness + 1;
                end else begin
                    if (brightness == 8'd0)   breath_dir <= 0;
                    else                      brightness <= brightness - 1;
                end
            end else begin
                breath_counter <= breath_counter + 1;
            end
        end
    end

    // ----------------------------------------------------------
    // Red flash timer: holds red for 80ms after packet_dropped,
    // then returns to previous state
    // 80ms @ 125 MHz = 10,000,000 cycles
    // ----------------------------------------------------------
    localparam RED_FLASH_CYCLES = 10_000_000;

    reg [23:0] red_flash_timer;
    reg        red_flash_active;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            red_flash_timer  <= 0;
            red_flash_active <= 0;
        end else begin
            if (packet_dropped) begin
                red_flash_active <= 1;
                red_flash_timer  <= RED_FLASH_CYCLES;
            end else if (red_flash_active) begin
                if (red_flash_timer == 0)
                    red_flash_active <= 0;
                else
                    red_flash_timer  <= red_flash_timer - 1;
            end
        end
    end

    // ----------------------------------------------------------
    // Color selector: pick GRB value for current state
    // WS2812B expects 24-bit GRB (not RGB) order
    // ----------------------------------------------------------
    // Steady green  : G=80  R=0   B=0   -> 24'h500000
    // Yellow breath : G=brightness R=brightness/2 B=0
    //                 (equal G+R makes yellow; G slightly stronger)
    // Red flash     : G=0   R=80  B=0   -> 24'h005000
    // ----------------------------------------------------------
    reg [23:0] led_color;   // GRB packed

    always @(*) begin
        if (red_flash_active || threat_level == MALICIOUS) begin
            // Red flash: G=0, R=80, B=0
            led_color = 24'h00_50_00;
        end else if (threat_level == SUSPICIOUS) begin
            // Yellow breathing: scale G and R with brightness
            // G = brightness, R = brightness >> 1 (gives warm yellow)
            led_color = {brightness, brightness[7:1], 1'b0, 8'h00};
        end else begin
            // Safe: steady soft green
            led_color = 24'h50_00_00;
        end
    end

    // ----------------------------------------------------------
    // WS2812B serializer FSM
    // Sends NUM_LEDS * 24 bits, then reset pulse, then repeats
    // ----------------------------------------------------------
    localparam S_IDLE    = 3'd0;
    localparam S_HIGH    = 3'd1;   // driving DIN high for T1H or T0H
    localparam S_LOW     = 3'd2;   // driving DIN low  for T1L or T0L
    localparam S_RESET   = 3'd3;   // reset gap
    localparam S_LOAD    = 3'd4;   // latch next LED color

    reg [2:0]  state;
    reg [7:0]  pulse_cnt;      // counts cycles within T1H/T0H/T1L/T0L
    reg [4:0]  bit_idx;        // 0-23, current bit within 24-bit word
    reg [4:0]  led_idx;        // 0-(NUM_LEDS-1), current LED
    reg [23:0] shift_reg;      // loaded with led_color for current LED
    reg        current_bit;    // bit being sent
    reg [12:0] reset_cnt;      // counts reset gap cycles

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state       <= S_LOAD;
            ws2812_din  <= 0;
            pulse_cnt   <= 0;
            bit_idx     <= 0;
            led_idx     <= 0;
            shift_reg   <= 0;
            current_bit <= 0;
            reset_cnt   <= 0;
        end else begin
            case (state)

                // Load color for current LED, grab MSB, start bit
                S_LOAD: begin
                    shift_reg   <= led_color;      // same color all LEDs
                    current_bit <= led_color[23];  // MSB first
                    bit_idx     <= 0;
                    state       <= S_HIGH;
                    pulse_cnt   <= 0;
                    ws2812_din  <= 1;
                end

                // Drive line high for T1H (bit=1) or T0H (bit=0)
                S_HIGH: begin
                    ws2812_din <= 1;
                    if (pulse_cnt >= (current_bit ? T1H : T0H) - 1) begin
                        pulse_cnt  <= 0;
                        ws2812_din <= 0;
                        state      <= S_LOW;
                    end else begin
                        pulse_cnt <= pulse_cnt + 1;
                    end
                end

                // Drive line low for T1L (bit=1) or T0L (bit=0)
                S_LOW: begin
                    ws2812_din <= 0;
                    if (pulse_cnt >= (current_bit ? T1L : T0L) - 1) begin
                        pulse_cnt <= 0;
                        // Advance to next bit or next LED
                        if (bit_idx == 23) begin
                            // Finished all 24 bits for this LED
                            if (led_idx == NUM_LEDS - 1) begin
                                // All LEDs done — reset gap
                                led_idx   <= 0;
                                state     <= S_RESET;
                                reset_cnt <= 0;
                            end else begin
                                led_idx     <= led_idx + 1;
                                bit_idx     <= 0;
                                // Preload next bit from shift reg
                                // (color is same for all LEDs here)
                                current_bit <= led_color[23];
                                state       <= S_HIGH;
                                ws2812_din  <= 1;
                            end
                        end else begin
                            // Next bit in same LED
                            bit_idx     <= bit_idx + 1;
                            current_bit <= shift_reg[22 - bit_idx]; // shift MSB down
                            state       <= S_HIGH;
                            ws2812_din  <= 1;
                        end
                    end else begin
                        pulse_cnt <= pulse_cnt + 1;
                    end
                end

                // Hold line low >= 50us to latch data into strip
                S_RESET: begin
                    ws2812_din <= 0;
                    if (reset_cnt >= TRESET - 1) begin
                        state <= S_LOAD;  // start next frame
                    end else begin
                        reset_cnt <= reset_cnt + 1;
                    end
                end

                default: state <= S_LOAD;
            endcase
        end
    end

endmodule

// ============================================================
// HASS - Shannon Entropy Calculator
// Flags payloads with H > threshold as suspicious
// Uses LUT-based entropy approximation (no floating point)
// Window: 256 bytes (one lookup table refresh per window)
// Target: Artix-7 XC7A100T @ 125 MHz
// ============================================================

module entropy_calc #(
    parameter WINDOW_SIZE  = 256,   // bytes per analysis window
    parameter ALERT_THRESH = 16'd896 // ~7.0 in Q9.7 fixed point
)(
    input  wire        clk,
    input  wire        rst_n,

    // Byte stream from TEMAC
    input  wire [7:0]  byte_in,
    input  wire        byte_valid,
    input  wire        frame_start,
    input  wire        frame_end,

    // Alert output
    output reg         entropy_alert,
    output reg [15:0]  entropy_value  // Q9.7 fixed point for debug
);

    // ----------------------------------------------------------
    // Stage 1: Frequency counter
    // 256 bins, each needing to count up to WINDOW_SIZE (256)
    // So 8 bits per bin, 256 bins = 2KB — fits in one RAMB18
    // ----------------------------------------------------------
    reg [7:0] freq [0:255];
    reg [7:0] byte_count;          // counts up to WINDOW_SIZE
    reg       window_done;         // pulses when window is full
    reg [8:0] actual_count;        // actual count of bytes in window

    integer i;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            byte_count  <= 0;
            window_done <= 0;
            actual_count <= 0;
            for (i = 0; i < 256; i = i + 1)
                freq[i] <= 0;
        end else begin
            window_done <= 0;

            if (frame_start) begin
                // Reset on new frame
                byte_count <= 0;
                for (i = 0; i < 256; i = i + 1)
                    freq[i] <= 0;
            end else if (frame_end) begin
                if (byte_count > 0) begin
                    window_done <= 1;
                    actual_count <= byte_count;
                end
            end else if (byte_valid) begin
                freq[byte_in] <= freq[byte_in] + 1;
                byte_count    <= byte_count + 1;

                if (byte_count == WINDOW_SIZE - 1) begin
                    window_done <= 1;
                    actual_count <= WINDOW_SIZE;
                    byte_count  <= 0;
                    // Clear for next window

                end
            end
        end
    end

    // ----------------------------------------------------------
    // Stage 2: Entropy accumulator
    // Iterates over all 256 bins after window_done
    // Uses NLGN LUT: maps frequency count f to f * log2(256/f)
    // scaled to Q9.7 fixed point
    //
    // nlgn_lut[f] = round(f * log2(256/f) * 128) for f in 0..256
    // This is precomputed — see Python snippet below to regenerate:
    //
    //   import math
    //   for f in range(257):
    //       if f == 0: print(0)
    //       else: print(round(f * math.log2(256/f) * 128))
    //
    // H = (1/256) * Σ nlgn_lut[freq[i]]  for all i
    // Equivalently: sum all nlgn_lut values, then right-shift by 8
    // ----------------------------------------------------------

    // LUT: nlgn_lut[f] for f = 0..256, stored as 16-bit values
    // Partial listing — synthesizer will implement as BRAM or LUTRAM
    reg [15:0] nlgn_lut [0:256];

    initial begin
        nlgn_lut[0] = 16'd0;
        nlgn_lut[1] = 16'd1024;
        nlgn_lut[2] = 16'd1792;
        nlgn_lut[3] = 16'd2463;
        nlgn_lut[4] = 16'd3072;
        nlgn_lut[5] = 16'd3634;
        nlgn_lut[6] = 16'd4159;
        nlgn_lut[7] = 16'd4653;
        nlgn_lut[8] = 16'd5120;
        nlgn_lut[9] = 16'd5564;
        nlgn_lut[10] = 16'd5988;
        nlgn_lut[11] = 16'd6393;
        nlgn_lut[12] = 16'd6781;
        nlgn_lut[13] = 16'd7154;
        nlgn_lut[14] = 16'd7513;
        nlgn_lut[15] = 16'd7859;
        nlgn_lut[16] = 16'd8192;
        nlgn_lut[17] = 16'd8514;
        nlgn_lut[18] = 16'd8824;
        nlgn_lut[19] = 16'd9125;
        nlgn_lut[20] = 16'd9416;
        nlgn_lut[21] = 16'd9697;
        nlgn_lut[22] = 16'd9970;
        nlgn_lut[23] = 16'd10235;
        nlgn_lut[24] = 16'd10491;
        nlgn_lut[25] = 16'd10740;
        nlgn_lut[26] = 16'd10981;
        nlgn_lut[27] = 16'd11215;
        nlgn_lut[28] = 16'd11442;
        nlgn_lut[29] = 16'd11663;
        nlgn_lut[30] = 16'd11878;
        nlgn_lut[31] = 16'd12086;
        nlgn_lut[32] = 16'd12288;
        nlgn_lut[33] = 16'd12484;
        nlgn_lut[34] = 16'd12675;
        nlgn_lut[35] = 16'd12861;
        nlgn_lut[36] = 16'd13041;
        nlgn_lut[37] = 16'd13216;
        nlgn_lut[38] = 16'd13386;
        nlgn_lut[39] = 16'd13551;
        nlgn_lut[40] = 16'd13712;
        nlgn_lut[41] = 16'd13868;
        nlgn_lut[42] = 16'd14019;
        nlgn_lut[43] = 16'd14166;
        nlgn_lut[44] = 16'd14308;
        nlgn_lut[45] = 16'd14447;
        nlgn_lut[46] = 16'd14581;
        nlgn_lut[47] = 16'd14712;
        nlgn_lut[48] = 16'd14838;
        nlgn_lut[49] = 16'd14961;
        nlgn_lut[50] = 16'd15079;
        nlgn_lut[51] = 16'd15194;
        nlgn_lut[52] = 16'd15306;
        nlgn_lut[53] = 16'd15414;
        nlgn_lut[54] = 16'd15518;
        nlgn_lut[55] = 16'd15619;
        nlgn_lut[56] = 16'd15717;
        nlgn_lut[57] = 16'd15811;
        nlgn_lut[58] = 16'd15902;
        nlgn_lut[59] = 16'd15990;
        nlgn_lut[60] = 16'd16075;
        nlgn_lut[61] = 16'd16157;
        nlgn_lut[62] = 16'd16235;
        nlgn_lut[63] = 16'd16311;
        nlgn_lut[64] = 16'd16384;
        nlgn_lut[65] = 16'd16454;
        nlgn_lut[66] = 16'd16521;
        nlgn_lut[67] = 16'd16585;
        nlgn_lut[68] = 16'd16647;
        nlgn_lut[69] = 16'd16706;
        nlgn_lut[70] = 16'd16762;
        nlgn_lut[71] = 16'd16815;
        nlgn_lut[72] = 16'd16866;
        nlgn_lut[73] = 16'd16914;
        nlgn_lut[74] = 16'd16960;
        nlgn_lut[75] = 16'd17003;
        nlgn_lut[76] = 16'd17044;
        nlgn_lut[77] = 16'd17083;
        nlgn_lut[78] = 16'd17119;
        nlgn_lut[79] = 16'd17152;
        nlgn_lut[80] = 16'd17183;
        nlgn_lut[81] = 16'd17212;
        nlgn_lut[82] = 16'd17239;
        nlgn_lut[83] = 16'd17264;
        nlgn_lut[84] = 16'd17286;
        nlgn_lut[85] = 16'd17306;
        nlgn_lut[86] = 16'd17324;
        nlgn_lut[87] = 16'd17339;
        nlgn_lut[88] = 16'd17353;
        nlgn_lut[89] = 16'd17364;
        nlgn_lut[90] = 16'd17374;
        nlgn_lut[91] = 16'd17381;
        nlgn_lut[92] = 16'd17387;
        nlgn_lut[93] = 16'd17390;
        nlgn_lut[94] = 16'd17391;
        nlgn_lut[95] = 16'd17391;
        nlgn_lut[96] = 16'd17388;
        nlgn_lut[97] = 16'd17383;
        nlgn_lut[98] = 16'd17377;
        nlgn_lut[99] = 16'd17369;
        nlgn_lut[100] = 16'd17359;
        nlgn_lut[101] = 16'd17347;
        nlgn_lut[102] = 16'd17333;
        nlgn_lut[103] = 16'd17317;
        nlgn_lut[104] = 16'd17300;
        nlgn_lut[105] = 16'd17281;
        nlgn_lut[106] = 16'd17260;
        nlgn_lut[107] = 16'd17237;
        nlgn_lut[108] = 16'd17212;
        nlgn_lut[109] = 16'd17186;
        nlgn_lut[110] = 16'd17158;
        nlgn_lut[111] = 16'd17129;
        nlgn_lut[112] = 16'd17098;
        nlgn_lut[113] = 16'd17065;
        nlgn_lut[114] = 16'd17030;
        nlgn_lut[115] = 16'd16994;
        nlgn_lut[116] = 16'd16957;
        nlgn_lut[117] = 16'd16917;
        nlgn_lut[118] = 16'd16877;
        nlgn_lut[119] = 16'd16834;
        nlgn_lut[120] = 16'd16790;
        nlgn_lut[121] = 16'd16745;
        nlgn_lut[122] = 16'd16698;
        nlgn_lut[123] = 16'd16649;
        nlgn_lut[124] = 16'd16599;
        nlgn_lut[125] = 16'd16547;
        nlgn_lut[126] = 16'd16494;
        nlgn_lut[127] = 16'd16440;
        nlgn_lut[128] = 16'd16384;
        nlgn_lut[129] = 16'd16327;
        nlgn_lut[130] = 16'd16268;
        nlgn_lut[131] = 16'd16208;
        nlgn_lut[132] = 16'd16146;
        nlgn_lut[133] = 16'd16083;
        nlgn_lut[134] = 16'd16018;
        nlgn_lut[135] = 16'd15953;
        nlgn_lut[136] = 16'd15885;
        nlgn_lut[137] = 16'd15817;
        nlgn_lut[138] = 16'd15747;
        nlgn_lut[139] = 16'd15676;
        nlgn_lut[140] = 16'd15603;
        nlgn_lut[141] = 16'd15529;
        nlgn_lut[142] = 16'd15454;
        nlgn_lut[143] = 16'd15378;
        nlgn_lut[144] = 16'd15300;
        nlgn_lut[145] = 16'd15221;
        nlgn_lut[146] = 16'd15141;
        nlgn_lut[147] = 16'd15059;
        nlgn_lut[148] = 16'd14976;
        nlgn_lut[149] = 16'd14892;
        nlgn_lut[150] = 16'd14807;
        nlgn_lut[151] = 16'd14720;
        nlgn_lut[152] = 16'd14632;
        nlgn_lut[153] = 16'd14543;
        nlgn_lut[154] = 16'd14453;
        nlgn_lut[155] = 16'd14362;
        nlgn_lut[156] = 16'd14269;
        nlgn_lut[157] = 16'd14175;
        nlgn_lut[158] = 16'd14080;
        nlgn_lut[159] = 16'd13984;
        nlgn_lut[160] = 16'd13887;
        nlgn_lut[161] = 16'd13788;
        nlgn_lut[162] = 16'd13689;
        nlgn_lut[163] = 16'd13588;
        nlgn_lut[164] = 16'd13486;
        nlgn_lut[165] = 16'd13383;
        nlgn_lut[166] = 16'd13279;
        nlgn_lut[167] = 16'd13174;
        nlgn_lut[168] = 16'd13068;
        nlgn_lut[169] = 16'd12960;
        nlgn_lut[170] = 16'd12852;
        nlgn_lut[171] = 16'd12742;
        nlgn_lut[172] = 16'd12631;
        nlgn_lut[173] = 16'd12520;
        nlgn_lut[174] = 16'd12407;
        nlgn_lut[175] = 16'd12293;
        nlgn_lut[176] = 16'd12178;
        nlgn_lut[177] = 16'd12062;
        nlgn_lut[178] = 16'd11945;
        nlgn_lut[179] = 16'd11827;
        nlgn_lut[180] = 16'd11708;
        nlgn_lut[181] = 16'd11588;
        nlgn_lut[182] = 16'd11466;
        nlgn_lut[183] = 16'd11344;
        nlgn_lut[184] = 16'd11221;
        nlgn_lut[185] = 16'd11097;
        nlgn_lut[186] = 16'd10972;
        nlgn_lut[187] = 16'd10846;
        nlgn_lut[188] = 16'd10718;
        nlgn_lut[189] = 16'd10590;
        nlgn_lut[190] = 16'd10461;
        nlgn_lut[191] = 16'd10331;
        nlgn_lut[192] = 16'd10200;
        nlgn_lut[193] = 16'd10068;
        nlgn_lut[194] = 16'd9935;
        nlgn_lut[195] = 16'd9801;
        nlgn_lut[196] = 16'd9666;
        nlgn_lut[197] = 16'd9530;
        nlgn_lut[198] = 16'd9394;
        nlgn_lut[199] = 16'd9256;
        nlgn_lut[200] = 16'd9117;
        nlgn_lut[201] = 16'd8978;
        nlgn_lut[202] = 16'd8837;
        nlgn_lut[203] = 16'd8696;
        nlgn_lut[204] = 16'd8554;
        nlgn_lut[205] = 16'd8410;
        nlgn_lut[206] = 16'd8266;
        nlgn_lut[207] = 16'd8121;
        nlgn_lut[208] = 16'd7975;
        nlgn_lut[209] = 16'd7829;
        nlgn_lut[210] = 16'd7681;
        nlgn_lut[211] = 16'd7533;
        nlgn_lut[212] = 16'd7383;
        nlgn_lut[213] = 16'd7233;
        nlgn_lut[214] = 16'd7082;
        nlgn_lut[215] = 16'd6930;
        nlgn_lut[216] = 16'd6777;
        nlgn_lut[217] = 16'd6623;
        nlgn_lut[218] = 16'd6469;
        nlgn_lut[219] = 16'd6313;
        nlgn_lut[220] = 16'd6157;
        nlgn_lut[221] = 16'd6000;
        nlgn_lut[222] = 16'd5842;
        nlgn_lut[223] = 16'd5683;
        nlgn_lut[224] = 16'd5524;
        nlgn_lut[225] = 16'd5363;
        nlgn_lut[226] = 16'd5202;
        nlgn_lut[227] = 16'd5040;
        nlgn_lut[228] = 16'd4877;
        nlgn_lut[229] = 16'd4713;
        nlgn_lut[230] = 16'd4549;
        nlgn_lut[231] = 16'd4383;
        nlgn_lut[232] = 16'd4217;
        nlgn_lut[233] = 16'd4051;
        nlgn_lut[234] = 16'd3883;
        nlgn_lut[235] = 16'd3714;
        nlgn_lut[236] = 16'd3545;
        nlgn_lut[237] = 16'd3375;
        nlgn_lut[238] = 16'd3204;
        nlgn_lut[239] = 16'd3033;
        nlgn_lut[240] = 16'd2860;
        nlgn_lut[241] = 16'd2687;
        nlgn_lut[242] = 16'd2513;
        nlgn_lut[243] = 16'd2339;
        nlgn_lut[244] = 16'd2163;
        nlgn_lut[245] = 16'd1987;
        nlgn_lut[246] = 16'd1810;
        nlgn_lut[247] = 16'd1632;
        nlgn_lut[248] = 16'd1454;
        nlgn_lut[249] = 16'd1275;
        nlgn_lut[250] = 16'd1095;
        nlgn_lut[251] = 16'd914;
        nlgn_lut[252] = 16'd733;
        nlgn_lut[253] = 16'd551;
        nlgn_lut[254] = 16'd368;
        nlgn_lut[255] = 16'd184;
        nlgn_lut[256] = 16'd0;
    end

    // Accumulator FSM
    localparam ACC_IDLE = 2'd0;
    localparam ACC_SUM  = 2'd1;
    localparam ACC_EVAL = 2'd2;

    reg [1:0]  acc_state;
    reg [7:0]  bin_idx;       // which freq bin we're reading
    reg [23:0] entropy_sum;   // accumulates nlgn_lut values
    reg [7:0]  freq_sample;   // registered freq read

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            acc_state    <= ACC_IDLE;
            bin_idx      <= 0;
            entropy_sum  <= 0;
            entropy_value <= 0;
            entropy_alert <= 0;
            freq_sample  <= 0;
        end else begin
            case (acc_state)

                ACC_IDLE: begin
                    entropy_alert <= 0;
                    if (window_done) begin
                        bin_idx     <= 0;
                        entropy_sum <= 0;
                        acc_state   <= ACC_SUM;
                    end
                end

                // One bin per cycle: read freq[bin_idx], add nlgn_lut entry
                // Takes 256 cycles = 2.048us @ 125 MHz — well within budget
                ACC_SUM: begin
                    freq_sample <= freq[bin_idx];
                    entropy_sum <= entropy_sum + nlgn_lut[freq[bin_idx]];
                    if (bin_idx == 8'hFF) begin
                        acc_state <= ACC_EVAL;
                    end else begin
                        bin_idx <= bin_idx + 1;
                    end
                end

                // Divide sum by 256 (right-shift 8) to get H in Q9.7
                ACC_EVAL: begin
                    $display("    DEBUG: entropy_sum=%0d actual_count=%0d", entropy_sum, actual_count);
                    entropy_value <= entropy_sum / actual_count;
                    entropy_alert <= (entropy_sum / actual_count >= ALERT_THRESH);
                    acc_state     <= ACC_IDLE;
                end

                default: acc_state <= ACC_IDLE;
            endcase
        end
    end

endmodule


import math

for f in range(257):
    if f == 0:
        print(f"nlgn_lut[{f}] = 16'd0;")
    else:
        val = round(f * math.log2(256 / f) * 128)
        print(f"nlgn_lut[{f}] = 16'd{val};")

# Simplification

There are some additional things we need to simplify in order
to do efficient symbolic execution.

## Example 1: instruction decoding

### Original
```
(
# previous PC
94_16 +

# condition
((MF8_MEM_prev[
# stored at location 0
0_16 := (((((0_7::RV32I_ADD_rs2)::RV32I_ADD_rs1)::0_3)::RV32I_ADD_rd)::51_7)[0:7]]

# stored at location 1
[1_16 := (((((0_7::RV32I_ADD_rs2)::RV32I_ADD_rs1)::0_3)::RV32I_ADD_rd)::51_7)[8:15]]

# stored at location 2
[2_16 := (((((0_7::RV32I_ADD_rs2)::RV32I_ADD_rs1)::0_3)::RV32I_ADD_rd)::51_7)[16:23]]

# stored at location 3
[3_16 := (((((0_7::RV32I_ADD_rs2)::RV32I_ADD_rs1)::0_3)::RV32I_ADD_rd)::51_7)[24:31]]

# access location 0
[((0_8::0_8) + 0_16)]

# check bit # 2
[2:2] = 0_1)

# increment by one or two
? 2_16 : 1_16)

)
```


### 1. Step: simplify read to location 0

```
(
# previous PC
94_16 +

# condition
(((((0_7::RV32I_ADD_rs2)::RV32I_ADD_rs1)::0_3)::RV32I_ADD_rd)::51_7)[0:7]
# check bit # 2
[2:2] = 0_1)

# increment by one or two
? 2_16 : 1_16)

)
```

### 2. Step: simplify extraxt with concrete ints

```
(
# previous PC
94_16 +

# condition
(RV32I_ADD_rd[0:0]::51_7)
# check bit # 2
[2:2] = 0_1)

# increment by one or two
? 2_16 : 1_16)

)
```

### 3. Step: simplify extract with concrete ints again

```
(
# previous PC
94_16 +

# condition
(51_7)[2:2] = 0_1

# increment by one or two
? 2_16 : 1_16)

)
```

### 4. Simplify condition involving constants:

```
(
# previous PC
94_16 +

# condition
false

# increment by one or two
? 2_16 : 1_16)

)
```

### 5. Step simplify the rest

```
(95_16)
```

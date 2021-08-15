#!/usr/bin/python3

def print_string(input):
    if input:
        for c in input:
            print(chr(c), end="")
    print(", ", end="")

def find_target():
    rescounter = []
    for i in range(0,4096):
        rescounter.append(0)
    for i in range(0x61,0x7a):
        input = []
        for j in range(0,4):
            input.append(i)
            res = calc_seed(input)
            rescounter[res] += 1
            if (rescounter[res] > 1):
                print("Collision at", hex(res), "between")
                return res

def brute_seed():
    target = find_target()
        
    for i in range(0x61,0x7a):
        input_string = []
        for j in range(0,4):
            input_string.append(i)
            res = calc_seed(input_string)
            if (res == target):
                print_string(input_string)

    print()

def test():
    tests = [[97, 97, 97, 97], [116]]
    for j in tests:
        print(hex(calc_seed(j)))

def calc_seed(input):
    seed = 2021
    for i in range(0,len(input)):
        seed = seed * 0x13377331 + input[i]
    # print(hex(seed & 0xfff))
    return (seed & 0xfff)

def main():
    brute_seed()

    test()

    # for i in range(0,4096):
    #     if len(collisions[i]) > 0:
    #         print(hex(i), ": ", collisions[i])
    trial = ['UUbtx', '7']
    for i in trial:
        input = []
        for j in i:
            input.append(ord(j))
        print(hex(calc_seed(input)))
        
if __name__ == "__main__": 
    main()
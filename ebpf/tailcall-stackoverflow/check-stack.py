# Copyright 2023 Leon Hwang.
# SPDX-License-Identifier: MIT


def check_final_result(args):
    nums = sorted(args)
    for n in nums:
        print("0x%x" % n)
    diffs = []
    for i in range(len(nums) - 1):
        diffs.append(nums[i + 1] - nums[i])
    print("Diffs:", diffs)
    print("Consumed stack space:", nums[-1] - nums[0], "bytes")


with open("run.log") as f:
    lines = f.readlines()
    args = []
    for line in lines:
        line = line.strip()
        if not line:
            continue

        fields = line.split()
        stack1, stack2 = fields[-3][:-1], fields[-1]
        args.append(int(stack1, 16))
        args.append(int(stack2, 16))

    check_final_result(args)

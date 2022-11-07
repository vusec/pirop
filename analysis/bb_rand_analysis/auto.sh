#!/bin/bash

echo ast_1_cp_40de
./analyze.py ast_1_cp_40de > ast_1_cp_40de.out.$1
./parse.py ast_1_cp_40de.out.$1 > ast_1_cp_40de.out.parsed.$1

echo ast_12_cp_cb18
./analyze.py ast_12_cp_cb18 > ast_12_cp_cb18.out.$1
./parse.py ast_12_cp_cb18.out.$1 > ast_12_cp_cb18.out.parsed.$1

echo ast_1_cp_5001a
./analyze.py ast_1_cp_5001a > ast_1_cp_5001a.out.$1
./parse.py ast_1_cp_5001a.out.$1 > ast_1_cp_5001a.out.parsed.$1

echo ast_2_cp_5001a
./analyze.py ast_2_cp_5001a > ast_2_cp_5001a.out.$1
./parse.py ast_2_cp_5001a.out.$1 > ast_2_cp_5001a.out.parsed.$1

echo ast_1_cp_ae88
./analyze.py ast_1_cp_ae88 > ast_1_cp_ae88.out.$1
./parse.py ast_1_cp_ae88.out.$1 > ast_1_cp_ae88.out.parsed.$1

echo ast_1_cp_bece
./analyze.py ast_1_cp_bece > ast_1_cp_bece.out.$1
./parse.py ast_1_cp_bece.out.$1 > ast_1_cp_bece.out.parsed.$1

echo ast_12_cp_c6f59 
./analyze.py ast_12_cp_c6f59 > ast_12_cp_c6f59.out.$1
./parse.py ast_12_cp_c6f59.out.$1 > ast_12_cp_c6f59.out.parsed.$1

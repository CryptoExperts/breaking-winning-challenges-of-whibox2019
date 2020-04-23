# Breaking \#111

1. Install prerequisite

  - Install `python`
  - Install python modules `pip install numpy tqdm`

2. Compile

  ```
  make
  ```

3. Launch the attack

  ```
  ./attack.sh
  ```


4. The attack will print out the 16 candidate key   bytes of the last round of AES
    ```
    5e 9b 16 11 9b 13 59 f8 23 b9 24 a0 03 91 45 db
    ```
    from which one can recover the full AES key:
    ```
    96 1d e5 14 84 9c 28 ef ae b9 6f 34 e1 40 7b 4b
    ```

# Breaking \#115

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
    51 61 e2 d8 8f a7 5b 0d 68 93 76 3d 70 95 10 c1
    ```
    from which one can recover the full AES key:
    ```
    91 2f 0f 37 fa 20 84 ab 2f 33 bc 48 7a df 8a 42
    ```

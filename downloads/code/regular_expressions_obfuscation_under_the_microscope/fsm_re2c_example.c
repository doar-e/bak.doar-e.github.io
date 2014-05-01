/* re2c -i fsm_re2c_example.c */
#include <stdio.h>
#include <string.h>

unsigned char checkinput(char* s)
{
    char *q;
/*!re2c
    re2c:define:YYCTYPE = "char";
    re2c:define:YYCURSOR = s;
    re2c:define:YYMARKER = q;
    re2c:yyfill:enable   = 0;

   "Hi-"[0-9]{4}  { return 1; }
   [^]            { return 0; }
*/
}

int main(int argc, char *argv[])
{
    if(argc != 2)
    {
        printf("./fsm <string>\n");
        return 0;
    }

    if(checkinput(argv[1]))
        printf("Good boy.\n");
    else
        printf("Bad boy.\n");

    return 1;
}

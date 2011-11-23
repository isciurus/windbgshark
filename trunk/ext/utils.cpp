#include "dbgexts.h"

void unescape(char *result, char *data)
{
    char ch;

    while ((ch = *(data++)) != 0) {
		if (ch == '\\') {
			if ((ch = *(data++)) == 0)
				break;

			switch (ch) {
			case 'a':				/* \a -> audible bell */
			ch = '\a';
			break;

			case 'b':				/* \b -> backspace */
			ch = '\b';
			break;

			case 'f':				/* \f -> formfeed */
			ch = '\f';
			break;

			case 'n':				/* \n -> newline */
			ch = '\n';
			break;

			case 'r':				/* \r -> carriagereturn */
			ch = '\r';
			break;

			case 't':				/* \t -> horizontal tab */
			ch = '\t';
			break;

			case 'v':				/* \v -> vertical tab */
			ch = '\v';
			break;

			case 'x':				/* \xnn -> ASCII value */
			if(*(data + 1) != 0)
				ch = strtol(data, NULL, 16);
			data += 2;

			break;

			default:				/* \any -> any */
			break;
			}
		}

		*result = ch;
		result++;
    }

	*result = 0;
}
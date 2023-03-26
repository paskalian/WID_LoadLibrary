#include "WID.h"

#pragma warning(disable : 6031)

int main()
{
	{
		WID::Loader::LOADLIBRARY Test("PATH_TO_DLL.dll");

		getchar();
	}

	getchar();
}
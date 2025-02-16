// Online C++ compiler to run C++ program online
#include <iostream>
#include <unistd.h>

using namespace std;

void loop(int j, string text, float time)
{
    for (int i = 0; i < j; i++)
    {
        cout << text;
        usleep(time * 1000000);
    }
}

int main()
{
    int i;
    cout << "DO NOT PRESS ENTER!";
    cin.get();
    cout << "LAST WARNING DONOT PRESS ENTER";
    cin.get();
    cout << "d";
    loop(5, "test\n", 0.5);
    return 0;
}
#include "menu.h"

int Menu::drawMenu(std::vector<std::string> menuOptions)
{
    int selectedOption = 0;
    int vectorSize = menuOptions.size();
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);

    bool selected = false;

    int ch;
    while (!selected)
    {
        clear();

        // Print the menu options
        for (int i = 0; i < vectorSize; ++i)
        {
            if (i == selectedOption)
            {
                attron(A_REVERSE);
            }
            printw("%s\n", menuOptions[i].c_str());
            attroff(A_REVERSE);
        }

        refresh();
        ch = getch();
        switch (ch)
        {
        case KEY_UP:
            if (selectedOption > 0)
            {
                selectedOption--;
            }
            break;

        case KEY_DOWN:
            if (selectedOption < vectorSize - 1)
            {
                selectedOption++;
            }
            break;

        case '\n':
            selected = true;
            break;
        }
    }

    endwin(); // Cleanup ncurses
    return selectedOption;
}
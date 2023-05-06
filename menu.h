#ifndef MENU_H
#define MENU_H

#include <iostream>
#include <vector>
#include <string>
#include <cstdlib>
#include <cstring>
#include <ncurses.h>

class Menu
{
public:
    int drawMenu(std::vector<std::string> menuOptions);
};

#endif

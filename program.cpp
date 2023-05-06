#include "program.h"

int main()
{
    std::vector<std::string> menuOptions;
    int menuSelection;
    Menu menu;

    Sniffer sniffer;
    pcap_if_t *interfaceList = nullptr;

    // get interface list
    if (!sniffer.getInterfaces(interfaceList))
    {
        return 1;
    }

    // add list to menuOptions vector
    int index = 1;
    for (pcap_if_t *iface = interfaceList; iface != nullptr; iface = iface->next)
    {
        menuOptions.push_back((std::string)iface->name);
        index++;
    }

    // draw menu and get the selection
    menuSelection = menu.drawMenu(menuOptions);
    std::cout << "Selected Interface:" << menuOptions[menuSelection] << std::endl;
    std::string fileName;
    std::cout << "Enter the file caputre name: (example: captured.pcap):" << std::endl;
    std::cin >> fileName;

    // get the selected interface
    if (!sniffer.startCapture(menuOptions[menuSelection].c_str(), fileName.c_str()))
    {
        std::cerr << "Error opening capture device" << std::endl;
        return 1;
    }

    return 0;
}
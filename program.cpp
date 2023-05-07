#include "program.h"

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        std::cout << "Usage: program <file_name>" << std::endl;
        return 1;
    }
    std::string fileName = argv[1];

    // if file doesn't exist caputre it
    if (!std::filesystem::exists(fileName))
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

        // get the selected interface
        if (!sniffer.startCapture(menuOptions[menuSelection].c_str(), fileName.c_str()))
        {
            std::cerr << "Error opening capture device" << std::endl;
            return 1;
        }
    }

    Analyzer packet_analyzer(fileName);

    return 0;
}
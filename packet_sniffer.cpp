#include "packet_sniffer.h"

bool Sniffer::getInterfaces(pcap_if_t *&interfaceList)
{
    char errBuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&interfaceList, errBuf) == -1)
    {
        std::cerr << "Error finding devices: " << errBuf << std::endl;
        return 0;
    }
    return 1;
}

bool Sniffer::startCapture(const char *selectedInterface, const char *pcapFileName)
{
    pcap_t *captureHandle;
    char errBuf[PCAP_ERRBUF_SIZE];

    // Open the capture interface
    captureHandle = pcap_open_live(selectedInterface, BUFSIZ, 1, 1000, errBuf);
    if (captureHandle == nullptr)
    {
        std::cerr << "Error opening capture device: " << errBuf << std::endl;
        return 0;
    }

    // Create a pcap_dumper_t handle for saving packets to file
    pcap_dumper_t *pcapDumper = pcap_dump_open(captureHandle, pcapFileName);
    if (pcapDumper == nullptr)
    {
        std::cerr << "Error creating pcap dumper: " << pcap_geterr(captureHandle) << std::endl;
        pcap_close(captureHandle);
        return 0;
    }

    // Start capturing and saving packets
    const u_char *packet;
    struct pcap_pkthdr packetHeader;
    bool stopCapturing = false;
    initscr();
    clear();
    printw("Caputre has started, to stop press q");
    refresh();
    cbreak();
    noecho();

    nodelay(stdscr, TRUE);

    keypad(stdscr, TRUE);

    while (!stopCapturing && (packet = pcap_next(captureHandle, &packetHeader)) != nullptr)
    {
        // Check for user input
        int ch = getch();
        if (ch != ERR)
        {
            if (ch == 'q' || ch == 'Q')
            {
                stopCapturing = true;
            }
        }

        // Write the packet to the pcap file
        pcap_dump((u_char *)pcapDumper, &packetHeader, packet);
    }

    pcap_dump_close(pcapDumper);
    pcap_close(captureHandle);
    clear();
    refresh();
    endwin();

    return 1;
}
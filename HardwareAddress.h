#ifndef __HARDWAREADDRESS_H__
#define __HARDWAREADDRESS_H__

class HardwareAddress
{
    public:
        unsigned char A;
        unsigned char B;
        unsigned char C;
        unsigned char D;
        unsigned char E;
        unsigned char F;

    bool operator==(const HardwareAddress &hwa) const;
};


#endif // __HARDWAREADDRESS_H__

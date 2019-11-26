#include "HardwareAddress.h"

bool HardwareAddress::operator==(const HardwareAddress &addy) const
{
    return((addy.A == this->A) &&
           (addy.B == this->B) &&
           (addy.C == this->C) &&
           (addy.D == this->D) &&
           (addy.E == this->E) &&
           (addy.F == this->F));
}

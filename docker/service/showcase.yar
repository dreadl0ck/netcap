rule Showcase_Legacy_Flash_Object : inventory
{
    meta:
        description = "Legacy Flash container magic; does not identify an exploit"
    condition:
        filesize >= 8 and uint8(3) > 0 and uint32(4) >= 8 and
        uint16(1) == 0x5357 and (uint8(0) == 0x46 or uint8(0) == 0x43 or uint8(0) == 0x5a)
}

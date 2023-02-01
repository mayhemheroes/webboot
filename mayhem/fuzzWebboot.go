package fuzzWebboot

import "strconv"
import "github.com/u-root/webboot/pkg/bootiso"
import "github.com/u-root/u-root/pkg/boot"
import "github.com/u-root/webboot/pkg/menu"
import "github.com/u-root/webboot/pkg/wpa/passphrase"
import fuzz "github.com/AdaLogics/go-fuzz-headers"


func mayhemit(bytes []byte) int {

    var num int
    if len(bytes) > 10 {
        num, _ = strconv.Atoi(string(bytes[0]))
        bytes = bytes[1:]

        switch num {
    
        case 0:

            fuzzConsumer := fuzz.NewConsumer(bytes)
            var part1 string
            var part2 string
            err := fuzzConsumer.CreateSlice(&part1)
            if err != nil {
                return 0
            }

            err = fuzzConsumer.CreateSlice(&part2)
            if err != nil {
                return 0
            }

            bootiso.ParseConfigFromISO(part1, part2)
            return 0

        case 1:
            fuzzConsumer := fuzz.NewConsumer(bytes)
            var part1 string
            var part2 string
            var part3 string
            err := fuzzConsumer.CreateSlice(&part1)
            if err != nil {
                return 0
            }

            err = fuzzConsumer.CreateSlice(&part2)
            if err != nil {
                return 0
            }

            err = fuzzConsumer.CreateSlice(&part3)
            if err != nil {
                return 0
            }

            bootiso.BootFromPmem(part1, part2, part3)
            return 0

        case 2:
            var test boot.OSImage

            fuzzConsumer := fuzz.NewConsumer(bytes)
            var content string
            err := fuzzConsumer.CreateSlice(&content)
            if err != nil {
                return 0
            }

            bootiso.BootCachedISO(test, content)

        case 3:
            fuzzConsumer := fuzz.NewConsumer(bytes)
            var part1 string
            var part2 string
            var part3 string
            err := fuzzConsumer.CreateSlice(&part1)
            if err != nil {
                return 0
            }

            err = fuzzConsumer.CreateSlice(&part2)
            if err != nil {
                return 0
            }

            err = fuzzConsumer.CreateSlice(&part3)
            if err != nil {
                return 0
            }

            bootiso.VerifyChecksum(part1, part2, part3)

        case 4:
            fuzzConsumerString := fuzz.NewConsumer(bytes)
            fuzzConsumerBoolean := fuzz.NewConsumer(bytes)
            var content string
            var boolean bool
            err := fuzzConsumerString.CreateSlice(&content)
            if err != nil {
                return 0
            }

            err = fuzzConsumerBoolean.CreateSlice(&boolean)
            if err != nil {
                return 0
            }

            menu.NewProgress(content, boolean)
            return 0

        default:
            fuzzConsumer := fuzz.NewConsumer(bytes[:len(bytes)/2])
            var part1 string
            var part2 string
            err := fuzzConsumer.CreateSlice(&part1)
            if err != nil {
                return 0
            }

            err = fuzzConsumer.CreateSlice(&part2)
            if err != nil {
                return 0
            }

            passphrase.Run(part1, part2)
            return 0

        }
    }
    return 0
}

func Fuzz(data []byte) int {
    _ = mayhemit(data)
    return 0
}
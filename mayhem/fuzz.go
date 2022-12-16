package fuzz

import "strconv"
import "github.com/u-root/webboot/pkg/bootiso"
import "github.com/u-root/u-root/pkg/boot"
import "github.com/u-root/webboot/pkg/menu"
import "github.com/u-root/webboot/pkg/wpa/passphrase"


func mayhemit(bytes []byte) int {

    var num int
    if len(bytes) > 2 {
        num, _ = strconv.Atoi(string(bytes[0]))
        bytes = bytes[1:]

        switch num {
    
        case 0:
            content := string(bytes)
            
            length := len(content)
            part1 := content[0:length/2]
            part2 := content[length/2:length]

            bootiso.ParseConfigFromISO(part1, part2)
            return 0

        case 1:
            content := string(bytes)

            length := len(content)
            part1 := content[0:length/3]
            part2 := content[length/3:2*(length/3)]
            part3 := content[2*(length/3):length]

            bootiso.BootFromPmem(part1, part2, part3)
            return 0

        case 2:
            var test boot.OSImage
            content := string(bytes)

            bootiso.BootCachedISO(test, content)

        case 3:
            content := string(bytes)

            length := len(content)
            part1 := content[0:length/3]
            part2 := content[length/3:2*(length/3)]
            part3 := content[2*(length/3):length]

            bootiso.VerifyChecksum(part1, part2, part3)

        case 4:
            content := string(bytes)
            menu.NewProgress(content, false)
            return 0

        // case 5:
        //     content := string(bytes)
        //     var test menu.Progress
        //     test.Update(content)
        //     return 0

        default:
            content := string(bytes)
            
            length := len(content)
            part1 := content[0:length/2]
            part2 := content[length/2:length]

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
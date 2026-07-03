# Guide for developers

This guide includes processes and advice for developers adding to this module.

## Modifying an existing Zephyr driver.

Sometimes you will want to change an existing driver. For example, Morse Micro has done this for the default STM32 SPI driver.

The decisions we have made for this process are:

- We will incorporate the original driver without code modification as the first step, but
- We will reformat the original driver as part of this first step so the driver remains consistent with other code in this repository.

This balances code consistency (_we want to be able `clang-format` any file we are working on_) and being able to trace the changes we make to vendored upstream drivers.

The steps for this process are:

1.  Create a new folder under `./drivers`, including adding a KConfig and CMakeLists.txt file.
1.  Update the existing `./drivers/KConfig` and `./drivers/CMakeLists.txt` to incorporate your new driver.
1.  Copy the original driver from Zephyr, formatting it with `clang-format` in the process.

    For example, this was the command used to create the STM32 "optim" SPI driver:

    ```
    clang-format ../../../zephyr/drivers/spi/spi_ll_stm32.c > drivers/spi/spi_ll_stm32_optim.c
    ```

1.  Add a comment to the copied file, explaining its origin (e.g. the file above changed name from `spi_ll_stm32.c` to `spi_ll_stm32_optim.c`)
1.  Update the `DT_DRV_COMPAT` and `LOG_MODULE_REGISTER` name to ensure you avoid conflicts.
1.  Add and/or update the copyright header in each file edited.
1.  Commit and push the change **prior** to continuing any improvements/changes, so future developers can trace the origin of the file and the subsequent edits. This is important if they want to rebase the edits onto an updated upstream driver.

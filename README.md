# SystemTweaker
Script with System utilities for Windows machines designed to enhance system configuration and management.

"SystemTweaker" is a script that provides various system utilities to streamline and optimize Windows machine settings. From self-updating capabilities to hostname customization, it aims to simplify common administrative tasks. Below are the completed and planned features:

## PLANNED

- **Configure the IP address:**
  - Allow the selection of the adapter
  - Allow the selection of additional options such as DNS, Gateway, etc.

- ***Create a domain (Windows Server Exclusive)***

- ***Join the domain***

- **Create system users:**
  - Set data by the user
  - Randomly

- ***Sysprep to join the domain***

- ***Edit the hosts file:*** (PowerToys allows editing it or it can possibly be opened with Notepad)

- ***Disable the firewall***


## COMPLETED

- ***Self-update capability:*** The script can update itself automatically, ensuring it always runs the latest code and improvements.

- ***Change the hostname:***
  - Allow the user to choose the hostname
  - Set a random hostname

## DETAILS

**Note:** Features marked with "<sup>**</sup>" are planned but have not been implemented yet.

### Self-update capability
This feature enables the script to update itself automatically without requiring users to download a new version. It ensures that the script always runs the latest code and improvements.

### Change the hostname
This feature provides users with the ability to change the hostname. Users can either manually choose a hostname or have the script set a random one.

### Configure the IP address <sup>**</sup>

This functionality will allow users to configure IP address settings, including the selection of the network adapter and additional options like DNS and Gateway settings.

### Create a domain (Windows Server Exclusive) <sup>**</sup>
This functionality is exclusive to Windows Server environments and aims to simplify domain setup and management tasks.

### Join the domain <sup>**</sup>
This feature will streamline the process of joining a system to an existing domain, enhancing network management.

### Create system users <sup>**</sup>
Users will be able to create system users with this feature. They can either manually provide user data or let the script generate user information randomly, improving system user management.

### Sysprep to join the domain <sup>**</sup>
This feature was initially designed with virtual machine images in mind, where multiple instances may share the same internal ID and require resetting for domain integration. It ensures a seamless and standardized domain integration process for such scenarios.

**Note:** This feature may be included by default, or users may have the option to enable it through questions related to the "Create domain" and "Join domain" features during the setup process.



### Edit the hosts file <sup>**</sup>
Users will have the ability to edit the hosts file using this feature. It may be possible to use tools like PowerToys for editing or open it directly with Notepad from the script.

### Disable the firewall <sup>**</sup>
This functionality will provide users with the ability to disable the firewall, useful for specific system configurations or network setups where firewall deactivation is necessary.




<?php
/**
 * This code is licensed under AGPLv3 license or Afterlogic Software License
 * if commercial version of the product was purchased.
 * For full statements of the licenses see LICENSE-AFTERLOGIC and LICENSE-AGPL3 files.
 */

namespace Aurora\Modules\AdminAuth;

use Aurora\System\SettingsProperty;

/**
 * @property bool $Disabled
 * @property array $SuperadminWhitelistIp
 * @property bool $AllowLoginFromCoreModule
 */

class Settings extends \Aurora\System\Module\Settings
{
    protected function initDefaults()
    {
        $this->aContainer = [
            "Disabled" => new SettingsProperty(
                false,
                "bool",
                null,
                "Setting to true disables the module",
            ),
            "SuperadminWhitelistIp" => new SettingsProperty(
                [],
                "array",
                null,
                "If non-empty, only listed IPs are allowed access from",
            ),
            "AllowLoginFromCoreModule" => new SettingsProperty(
                false,
                "bool",
                null,
                "If set to true, superadmin account is allowed to log into main login page",
            ),
        ];
    }
}

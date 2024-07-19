<?php
/**
 * This code is licensed under AGPLv3 license or Afterlogic Software License
 * if commercial version of the product was purchased.
 * For full statements of the licenses see LICENSE-AFTERLOGIC and LICENSE-AGPL3 files.
 */

namespace Aurora\Modules\AdminAuth;

use Aurora\Modules\Core\Module as CoreModule;

/**
 * This module adds ability to login to the admin panel as a Super Administrator.
 *
 * @license https://www.gnu.org/licenses/agpl-3.0.html AGPL-3.0
 * @license https://afterlogic.com/products/common-licensing Afterlogic Software License
 * @copyright Copyright (c) 2023, Afterlogic Corp.
 *
 * @property Settings $oModuleSettings
 *
 * @package Modules
 */
class Module extends \Aurora\System\Module\AbstractModule
{
    /**
     * @return Module
     */
    public static function getInstance()
    {
        return parent::getInstance();
    }

    /**
     * @return Module
     */
    public static function Decorator()
    {
        return parent::Decorator();
    }

    /**
     * @return Settings
     */
    public function getModuleSettings()
    {
        return $this->oModuleSettings;
    }

    /***** private functions *****/
    /**
     * @return void
     */
    public function init()
    {
        $this->subscribeEvent('Login', array($this, 'onLogin'), 10);
        $this->subscribeEvent('CheckAccountExists', array($this, 'onCheckAccountExists'));
        $this->subscribeEvent('System::RunEntry::before', array($this, 'onBeforeRunEntry'));
    }

    public function LoginAsSuperadmin($Login, $Password)
    {
        \Aurora\System\Api::checkUserRoleIsAtLeast(\Aurora\System\Enums\UserRole::Anonymous);

        $aAuthData = self::Decorator()->Login($Login, $Password);

        return CoreModule::Decorator()->SetAuthDataAndGetAuthToken($aAuthData);
    }

    public function Login($Login, $Password)
    {
        $sIp = \Aurora\System\Utils::getClientIp();
        CoreModule::Decorator()->IsBlockedUser($Login, $sIp);

        $mResult = false;
        $oSettings = &\Aurora\System\Api::GetSettings();
        if ($Login === $oSettings->AdminLogin) {
            if ($this->isClientIpInWhitelist()) {
                $sAdminPassword = $oSettings->AdminPassword;
                $bCorrectEmptyPass = empty($Password) && empty($sAdminPassword);
                $bCorrectPass = password_verify(trim($Password), $sAdminPassword);

                if ($bCorrectEmptyPass || $bCorrectPass) {
                    $mResult = [
                        'token' => 'admin',
                        'id' => '-1'
                    ];
                }
            }
        }

        if (!$mResult) {
            CoreModule::Decorator()->BlockUser($Login, $sIp);
            CoreModule::Decorator()->IsBlockedUser($Login, $sIp);
        } else {
            $oBlockedUser = CoreModule::Decorator()->GetBlockedUser($Login, $sIp);
            if ($oBlockedUser) {
                $oBlockedUser->delete();
            }
        }

        return $mResult;
    }

    /**
     * Checks if superadmin has specified login.
     *
     * @param array $aArgs
     *
     * @throws \Aurora\System\Exceptions\ApiException
     */
    public function onCheckAccountExists($aArgs)
    {
        $oSettings = &\Aurora\System\Api::GetSettings();
        if ($aArgs['Login'] === $oSettings->AdminLogin) {
            throw new \Aurora\System\Exceptions\ApiException(\Aurora\System\Notifications::AccountExists);
        }
    }

    /**
     * Tries to log in with specified credentials.
     *
     * @param array $aArgs Parameters contain the required credentials.
     * @param array|mixed $mResult Parameter is passed by reference for further filling with result. Result is the array with data for authentication token.
     */
    public function onLogin(&$aArgs, &$mResult)
    {
        $bAllowLoginFromCoreModule = $this->oModuleSettings->AllowLoginFromCoreModule;
        $oSettings = &\Aurora\System\Api::GetSettings();
        if ($bAllowLoginFromCoreModule && $aArgs['Login'] === $oSettings->AdminLogin) {
            $mResult = $this->Login($aArgs['Login'], $aArgs['Password']);
            return true;
        }
    }

    protected function isClientIpInWhitelist()
    {
        $mResult = true;

        $aWhitelistIp = $this->oModuleSettings->SuperadminWhitelistIp;
        $ip = \Aurora\System\Utils::getClientIp();

        if (!empty($ip) && count($aWhitelistIp) > 0 && !in_array($ip, $aWhitelistIp)) {
            $mResult = false;
        }

        return $mResult;
    }

    public function onBeforeRunEntry(&$aArgs, &$mResult)
    {
        $oAuthenticatedUser = \Aurora\System\Api::getAuthenticatedUser();
        if ($oAuthenticatedUser instanceof \Aurora\Modules\Core\Models\User &&
            $oAuthenticatedUser->Role === \Aurora\System\Enums\UserRole::SuperAdmin && !$this->isClientIpInWhitelist()) {
            if (isset($aArgs['EntryName']) && strtolower($aArgs['EntryName']) === 'default') {
                CoreModule::Decorator()->Logout();
            } else {
                $mResult = \Aurora\System\Managers\Response::GetJsonFromObject(
                    'Json',
                    \Aurora\System\Managers\Response::ExceptionResponse(
                        'RunEntry',
                        new \Aurora\System\Exceptions\ApiException(
                            \Aurora\System\Notifications::AccessDenied,
                            null,
                            $this->i18N('ERROR_USER_ACCESS_DENIED'),
                            [],
                            $this
                        )
                    )
                );
                return true;
            }
        }
    }
    /***** private functions *****/
}

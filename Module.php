<?php
/**
 * This code is licensed under AGPLv3 license or Afterlogic Software License
 * if commercial version of the product was purchased.
 * For full statements of the licenses see LICENSE-AFTERLOGIC and LICENSE-AGPL3 files.
 */
 
namespace Aurora\Modules\AdminAuth;

/**
 * This module adds ability to login to the admin panel as a Super Administrator.
 *
 * @license https://www.gnu.org/licenses/agpl-3.0.html AGPL-3.0
 * @license https://afterlogic.com/products/common-licensing Afterlogic Software License
 * @copyright Copyright (c) 2019, Afterlogic Corp.
 *
 * @package Modules
 */
class Module extends \Aurora\System\Module\AbstractModule
{
	/***** private functions *****/
	/**
	 * @return array
	 */
	public function init()
	{
		$this->subscribeEvent('Login', array($this, 'onLogin'), 10);
		$this->subscribeEvent('CheckAccountExists', array($this, 'onCheckAccountExists'));
		$this->subscribeEvent('System::RunEntry::before', array($this, 'onBeforeRunEntry'));
	}
	
	/**
	 * Return crypted password.
	 * 
	 * @param string $Password
	 * @return string
	 */
	public function CryptPassword($Password)
	{
		return crypt(trim($Password), \Aurora\System\Api::$sSalt);
	}

	/**
	 * Checks if superadmin has specified login.
	 * 
	 * @param string $sLogin Login for checking.
	 * 
	 * @throws \Aurora\System\Exceptions\ApiException
	 */
	public function onCheckAccountExists($aArgs)
	{
		$oSettings =&\Aurora\System\Api::GetSettings();
		if ($aArgs['Login'] === $oSettings->AdminLogin)
		{
			throw new \Aurora\System\Exceptions\ApiException(\Aurora\System\Notifications::AccountExists);
		}
	}

	/**
	 * Tries to log in with specified credentials.
	 * 
	 * @param array $aParams Parameters contain the required credentials.
	 * @param array|mixed $mResult Parameter is passed by reference for further filling with result. Result is the array with data for authentication token.
	 */
	public function onLogin(&$aArgs, &$mResult)
	{
		$oSettings =&\Aurora\System\Api::GetSettings();
		$sAdminPassword = $oSettings->AdminPassword;
		
		$bCorrectEmptyPass = empty($aArgs['Password']) && empty($sAdminPassword);
		
		$bCorrectPass = $this->cryptPassword($aArgs['Password']) === $oSettings->AdminPassword;
		
		if ($aArgs['Login'] === $oSettings->AdminLogin)
		{
			if ($bCorrectEmptyPass || $bCorrectPass)
			{
				if (!$this->isClientIpInWhitelist())
				{
					$mResult = false;
					return true;
				}

				$mResult = array(
					'token' => 'admin',
					'id' => '-1'
				);
			}
			else
			{
				$mResult = false;
			}
			return true;
		}
	}

	protected function isClientIpInWhitelist()
	{
		$mResult = true;

		$aWhitelistIp = $this->getConfig('SuperadminWhitelistIp', []);
		$ip = \Aurora\System\Utils::getClientIp();
					
		if (!empty($ip) && count($aWhitelistIp) > 0 && !in_array($ip, $aWhitelistIp))
		{
			$mResult = false;
		}

		return $mResult;
	}

	public function onBeforeRunEntry(&$aArgs, &$mResult)
	{
		$oAuthenticatedUser = \Aurora\System\Api::getAuthenticatedUser();
		if ($oAuthenticatedUser instanceof \Aurora\Modules\Core\Classes\User && 
			$oAuthenticatedUser->Role === \Aurora\System\Enums\UserRole::SuperAdmin && !$this->isClientIpInWhitelist())
		{
			if (isset($aArgs['EntryName']) && strtolower($aArgs['EntryName']) === 'default')
			{
				\Aurora\Modules\Core\Module::Decorator()->Logout();
			}
			else
			{
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

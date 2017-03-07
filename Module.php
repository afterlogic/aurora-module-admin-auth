<?php
/**
 * @copyright Copyright (c) 2017, Afterlogic Corp.
 * @license AGPL-3.0
 *
 * This code is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License, version 3,
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 * 
 * @package Modules
 */

namespace Aurora\Modules\AdminAuth;

class Module extends \Aurora\System\Module\AbstractModule
{
	/***** private functions *****/
	/**
	 * @return array
	 */
	public function init()
	{
		$this->subscribeEvent('Login', array($this, 'onLogin'));
		$this->subscribeEvent('CheckAccountExists', array($this, 'onCheckAccountExists'));
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
		if ($aArgs['Login'] === $oSettings->GetConf('AdminLogin'))
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
		
		$bCorrectEmptyPass = empty($aArgs['Password']) && empty($oSettings->GetConf('AdminPassword'));
		
		$bCorrectPass = crypt(trim($aArgs['Password']), \Aurora\System\Api::$sSalt) === $oSettings->GetConf('AdminPassword');
		
		if ($aArgs['Login'] === $oSettings->GetConf('AdminLogin') && ($bCorrectEmptyPass || $bCorrectPass))
		{
			$mResult = array(
				'token' => 'admin'
			);
			return true;
		}
	}
	/***** private functions *****/
}

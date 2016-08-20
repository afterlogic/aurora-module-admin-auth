<?php

class AdminAuthModule extends AApiModule
{
	/***** private functions *****/
	/**
	 * @return array
	 */
	public function init()
	{
		$this->subscribeEvent('Login', array($this, 'checkAuth'));
		$this->subscribeEvent('CheckAccountExists', array($this, 'checkAccountExists'));
	}

	/**
	 * Checks if superadmin has specified login.
	 * 
	 * @param string $sLogin Login for checking.
	 * 
	 * @throws \System\Exceptions\AuroraApiException
	 */
	public function checkAccountExists($sLogin)
	{
		$oSettings =& CApi::GetSettings();
		if ($sLogin === $oSettings->GetConf('AdminLogin'))
		{
			throw new \System\Exceptions\AuroraApiException(\System\Notifications::AccountExists);
		}
	}

	/**
	 * Tries to log in with specified credentials.
	 * 
	 * @param array $aParams Parameters contain the required credentials.
	 * @param array|mixed $mResult Parameter is passed by reference for further filling with result. Result is the array with data for authentication token.
	 */
	public function checkAuth($aParams, &$mResult)
	{
		$sLogin = $aParams['Login'];
		$sPassword = $aParams['Password'];
		
		$oSettings =& CApi::GetSettings();
		
		$bCorrectEmptyPass = empty($sPassword) && empty($oSettings->GetConf('AdminPassword'));
		
		$bCorrectPass = crypt(trim($sPassword), \CApi::$sSalt) === $oSettings->GetConf('AdminPassword');
		
		if ($sLogin === $oSettings->GetConf('AdminLogin') && ($bCorrectEmptyPass || $bCorrectPass))
		{
			$mResult = array(
				'token' => 'admin'
			);
		}
	}
	/***** private functions *****/
}

<?php

class AdminAuthModule extends AApiModule
{
	/**
	 * @return array
	 */
	public function init()
	{
		$this->subscribeEvent('Login', array($this, 'checkAuth'));
	}

	public function checkAuth($aParams, &$mResult)
	{
		$sLogin = $aParams['Login'];
		$sPassword = $aParams['Password'];
		
		$oSettings =& CApi::GetSettings();
		if ($sLogin === $oSettings->GetConf('AdminLogin') && md5(trim($sPassword)) === $oSettings->GetConf('AdminPassword'))
		{
			$mResult = array(
				'token' => 'admin'
			);
		}
	}
}

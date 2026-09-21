import React, { useEffect, useRef, useState } from 'react'
import { Input } from '@heroui/react'
import { useTranslation } from 'react-i18next'
import { useAppConfig } from '@renderer/hooks/use-app-config'
import { toast } from '@renderer/components/base/toast'
import SettingItem from '../base/base-setting-item'

type ProviderKey = 'ipPurityAbuseIPDBApiKey' | 'ipPurityIpapiApiKey'

const KeyInput: React.FC<{ name: ProviderKey; saved: string }> = ({ name, saved }) => {
  const { t } = useTranslation()
  const { patchAppConfig } = useAppConfig()
  const [value, setValue] = useState(saved)
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const latest = useRef(saved)
  useEffect(() => { setValue(saved); latest.current = saved }, [saved])
  useEffect(() => () => { if (timer.current) clearTimeout(timer.current) }, [])
  const save = (text: string): void => {
    if (timer.current) clearTimeout(timer.current)
    timer.current = undefined
    void patchAppConfig({ [name]: text.trim() }).catch(() => toast.error(t('proxies.purity.details.saveFailed')))
  }
  return <Input
    type="password"
    autoComplete="off"
    size="sm"
    className="w-[60%]"
    aria-label={name === 'ipPurityAbuseIPDBApiKey' ? 'AbuseIPDB API Key' : 'ipapi.is API Key'}
    value={value}
    placeholder={t('proxies.purity.details.keyHint')}
    onValueChange={(text) => {
      setValue(text)
      latest.current = text
      if (timer.current) clearTimeout(timer.current)
      timer.current = setTimeout(() => save(text), 500)
    }}
    onBlur={() => save(latest.current)}
  />
}

const PurityProviderSettings: React.FC = () => {
  const { appConfig } = useAppConfig()
  return <>
    <SettingItem title="AbuseIPDB API Key" divider>
      {appConfig && <KeyInput name="ipPurityAbuseIPDBApiKey" saved={appConfig.ipPurityAbuseIPDBApiKey ?? ''} />}
    </SettingItem>
    <SettingItem title="ipapi.is API Key" divider>
      {appConfig && <KeyInput name="ipPurityIpapiApiKey" saved={appConfig.ipPurityIpapiApiKey ?? ''} />}
    </SettingItem>
  </>
}

export default PurityProviderSettings

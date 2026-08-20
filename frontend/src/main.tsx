import React from 'react'
import ReactDOM from 'react-dom/client'
import { ConfigProvider } from 'antd'
import zhCN from 'antd/locale/zh_CN'
import App from './App'
import './styles.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ConfigProvider
      locale={zhCN}
      theme={{
        token: {
          colorPrimary: '#176b87',
          colorInfo: '#176b87',
          colorSuccess: '#17825c',
          colorWarning: '#b86b11',
          colorError: '#c53b3b',
          borderRadius: 8,
          fontFamily: "Inter, 'Microsoft YaHei UI', 'PingFang SC', sans-serif",
        },
      }}
    >
      <App />
    </ConfigProvider>
  </React.StrictMode>,
)

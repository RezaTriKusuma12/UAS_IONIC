import type { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.logista',
  appName: 'Logista',
  webDir: 'www',

  plugins: {

  SplashScreen: {

    launchShowDuration: 2500,

    launchAutoHide: true,

    backgroundColor: "#081229",

    androidSplashResourceName: "splash",

    androidScaleType: "CENTER_CROP",

    showSpinner: false

  }

}
};



export default config;

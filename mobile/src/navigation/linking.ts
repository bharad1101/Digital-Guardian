import type { LinkingOptions } from "@react-navigation/native";

import type { RootStackParamList } from "./types";

/**
 * Deep-link configuration. This lets other apps hand content to Digital
 * Guardian through the custom scheme, e.g.:
 *
 *   digitalguardian://share?text=<url-encoded message>
 *   digitalguardian://share?url=https%3A%2F%2Fexample.com
 *
 * True Android `ACTION_SEND` share-sheet integration additionally needs a
 * native intent filter / share extension (see README "Mobile: sharing"), but
 * this deep-link path works in Expo Go and development builds today.
 */
export const linking: LinkingOptions<RootStackParamList> = {
  prefixes: ["digitalguardian://"],
  config: {
    screens: {
      Tabs: {
        screens: {
          Dashboard: "dashboard",
          Scan: "scan",
          Lens: "lens",
          History: "history",
          Settings: "settings",
        },
      },
      Result: "result",
      ScanDetail: "scan/:id",
      ReceiveShare: {
        path: "share",
        parse: {
          text: (value: string) => value,
          url: (value: string) => value,
        },
      },
    },
  },
};

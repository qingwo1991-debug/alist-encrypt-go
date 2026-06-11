import 'package:flutter/material.dart';

class DividerPreference extends StatelessWidget {
  const DividerPreference({super.key, required this.title});

  final String title;

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 20, 16, 4),
      child: Row(
        children: [
          Container(
            width: 3,
            height: 16,
            decoration: BoxDecoration(
              color: colorScheme.primary,
              borderRadius: BorderRadius.circular(2),
            ),
          ),
          const SizedBox(width: 10),
          Text(
            title,
            style: Theme.of(context).textTheme.titleSmall?.copyWith(
                  color: colorScheme.primary,
                  fontWeight: FontWeight.w600,
                  letterSpacing: 0.3,
                ),
          ),
        ],
      ),
    );
  }
}

class BasicPreference extends StatelessWidget {
  final String title;
  final String subtitle;
  final Widget? leading;
  final Widget? trailing;
  final GestureTapCallback? onTap;

  const BasicPreference({
    super.key,
    required this.title,
    required this.subtitle,
    this.onTap,
    this.leading,
    this.trailing,
  });

  @override
  Widget build(BuildContext context) {
    return ListTile(
      title: Text(title),
      subtitle: Text(subtitle),
      leading: leading,
      trailing: trailing,
      onTap: onTap,
    );
  }
}

class SwitchPreference extends StatelessWidget {
  const SwitchPreference({
    super.key,
    required this.title,
    required this.subtitle,
    this.icon,
    required this.value,
    required this.onChanged,
  });

  final String title;
  final String subtitle;
  final Widget? icon;
  final bool value;
  final ValueChanged<bool> onChanged;

  @override
  Widget build(BuildContext context) {
    return BasicPreference(
      title: title,
      subtitle: subtitle,
      leading: icon,
      trailing: Switch(value: value, onChanged: onChanged),
      onTap: () {
        onChanged(!value);
      },
    );
  }
}

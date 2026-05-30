import 'dart:async';

import 'package:flutter/material.dart';
import '../../generated/l10n.dart';

class PwdEditDialog extends StatefulWidget {
  final Future<String?> Function(String) onConfirm;

  const PwdEditDialog({super.key, required this.onConfirm});

  @override
  State<PwdEditDialog> createState() {
    return _PwdEditDialogState();
  }
}

class _PwdEditDialogState extends State<PwdEditDialog>
    with SingleTickerProviderStateMixin {
  final TextEditingController pwdController = TextEditingController();
  String? _errorText;
  bool _isSubmitting = false;
  bool _obscureText = true;

  @override
  void dispose() {
    pwdController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: Text(S.of(context).modifyAdminPassword),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          TextField(
            controller: pwdController,
            enabled: !_isSubmitting,
            obscureText: _obscureText,
            decoration: InputDecoration(
              labelText: "admin密码",
              suffixIcon: IconButton(
                onPressed: _isSubmitting
                    ? null
                    : () {
                        setState(() {
                          _obscureText = !_obscureText;
                        });
                      },
                icon: Icon(
                  _obscureText ? Icons.visibility : Icons.visibility_off,
                ),
              ),
            ),
          ),
          if (_errorText != null) ...[
            const SizedBox(height: 12),
            Text(
              _errorText!,
              style: const TextStyle(color: Colors.red, fontSize: 12),
            ),
          ],
        ],
      ),
      actions: [
        TextButton(
          onPressed: _isSubmitting
              ? null
              : () {
                  Navigator.of(context).pop();
                },
          child: Text(S.of(context).cancel),
        ),
        FilledButton(
          onPressed: _isSubmitting ? null : () async {
            final password = pwdController.text.trim();
            if (password.length < 4) {
              setState(() {
                _errorText = '管理员密码至少需要 4 位';
              });
              return;
            }

            setState(() {
              _isSubmitting = true;
              _errorText = null;
            });

            final error = await widget.onConfirm(password).timeout(
              const Duration(seconds: 20),
              onTimeout: () => '管理员密码更新超时，请稍后重试。',
            );
            if (!mounted) return;

            if (error == null) {
              Navigator.of(context).pop();
              return;
            }

            setState(() {
              _isSubmitting = false;
              _errorText = error;
            });
          },
          child: _isSubmitting
              ? const SizedBox(
                  width: 18,
                  height: 18,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : Text(S.of(context).confirm),
        ),
      ],
    );
  }
}
